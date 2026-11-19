#!/usr/bin/env bash
#
# mayhem/build.sh — build OpenSMTPD's fuzz harnesses and its known-answer test.
#
# Out-of-tree autotools builds of the whole project (smtpd, smtpctl, ...):
#   mayhem/build/fuzz    $SANITIZER_FLAGS $DEBUG_FLAGS + SanCov (-fsanitize=fuzzer-no-link)
#   mayhem/build/normal  the project's normal flags (oracle for mayhem/test.sh)
# Each harness in mayhem/harnesses links the objects automake links smtpd(8)
# from (read from mk/smtpd/Makefile), with smtpd.c's main() renamed, into
#   mayhem/out/<harness>             libFuzzer binary (Mayhem target)
#   mayhem/out/<harness>-standalone  run-once reproducer ($STANDALONE_FUZZ_MAIN)
# plus a third build, mayhem/build/afl, for the AFL++ (whole-process) targets
#   mayhem/out/smtpd-afl         smtpd(8) itself: the smtpd.conf target
#   mayhem/out/sendmail-enqueue  smtpctl(8)'s sendmail mode (enqueue.c), linked
#                                from smtpctl's objects with smtpctl.c's main() renamed
# Re-runnable and offline: only apt-installed headers/libs are used.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=$(cd "$(dirname "$0")/.." && pwd)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B="$SRC/mayhem/build"
OUT="$SRC/mayhem/out"
mkdir -p "$B/fuzz" "$B/normal" "$OUT"

# configure & co. are generated (and gitignored upstream): regenerate when absent.
[ -x configure ] || ./bootstrap

CONFIGURE_ARGS=(--with-gnu-ld --sysconfdir=/etc/mail)

# 1) the project, sanitized and coverage-instrumented
#    SanCov is unconditional, also when SANITIZER_FLAGS is empty. The ASan/UBSan
#    runtimes define the __sanitizer_cov_* callbacks; without a sanitizer they come
#    from clang's libFuzzer-without-main, through LIBS, so configure's link probes,
#    the fuzz tree's programs and the -standalone reproducers all link. (The
#    libFuzzer links take libclang_rt.fuzzer --whole-archive first, so this
#    archive adds nothing to them.) -lresolv is what the ASan/UBSan link adds
#    implicitly; with it configure's probes come out as in the sanitized build.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
SANCOV_LIBS=""
if [ -z "$SANITIZER_FLAGS" ]; then
	SANCOV_LIBS="-L$(dirname "$($CC -print-file-name=libclang_rt.fuzzer_no_main-x86_64.a)") -lclang_rt.fuzzer_no_main-x86_64 -lstdc++ -lm -lpthread -lresolv"
fi
(
	cd "$B/fuzz"
	[ -f config.status ] || "$SRC/configure" "${CONFIGURE_ARGS[@]}" CC="$CC" CFLAGS="$FUZZ_CFLAGS" LIBS="$SANCOV_LIBS"
	make -j"$MAYHEM_JOBS"
)

# 1b) the project again with AFL++ instrumentation (same sanitizers): smtpd(8)
#     itself is the smtpd.conf target (`smtpd -n -f <file>`, Mayhemfile afl: true),
#     so each config parse runs in a fresh process. LeakSanitizer is turned off
#     at link time through LIBS.
mkdir -p "$B/afl"
# shellcheck disable=SC2086
afl-clang-fast $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$B/afl/lsan_off.o"
(
	cd "$B/afl"
	[ -f config.status ] || "$SRC/configure" "${CONFIGURE_ARGS[@]}" CC=afl-clang-fast \
		CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" LIBS="$B/afl/lsan_off.o"
	AFL_QUIET=1 make -j"$MAYHEM_JOBS"
)
cp -f "$B/afl/mk/smtpd/smtpd" "$OUT/smtpd-afl"

# 2) the project with its normal flags, for the test oracle
(
	cd "$B/normal"
	[ -f config.status ] || "$SRC/configure" "${CONFIGURE_ARGS[@]}" CC="$CC" \
		CFLAGS="-g -O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS"
	make -j"$MAYHEM_JOBS"
)

# automake's include flags are relative to mk/<program>, so every compile below
# runs from there.
mk() { make -s -C "$1/mk/$PROG" -f Makefile -f "$SRC/mayhem/print-objs.mk" PROG="$PROG" "$2" 2>/dev/null; }

# harness_env <build dir> <cflags> <program> [<cc>]: set CPPFLAGS_H (preprocessor
# flags and automake's AM_CFLAGS) / LIBS_H / OBJS_H to what <program> (smtpd or
# smtpctl) is compiled and linked with;
# <program>.c is recompiled with main() renamed to <program>_main.
harness_env() {
	local bd="$1" cflags="$2" cc="${4:-$CC}" o
	PROG="$3"
	CPPFLAGS_H="$(mk "$bd" print-cppflags) $(mk "$bd" print-cflags) -I$bd -I$SRC/usr.sbin/smtpd -I$SRC/openbsd-compat -I$SRC/openbsd-compat/libtls"
	LIBS_H="$(mk "$bd" print-libs)"
	# shellcheck disable=SC2086
	(cd "$bd/mk/$PROG" && $cc $cflags $CPPFLAGS_H -Dmain="${PROG}_main" \
		-c "$SRC/usr.sbin/smtpd/$PROG.c" -o "$bd/${PROG}_main.o")
	OBJS_H=()
	for o in $(mk "$bd" print-objs); do
		case "$o" in
		*/usr.sbin/smtpd/"$PROG".o | */usr.sbin/smtpd/"$PROG-$PROG".o)
			o="$bd/${PROG}_main.o" ;;
		esac
		case "$o" in /*) ;; *) o="$bd/mk/$PROG/$o" ;; esac
		OBJS_H+=("$o")
	done
}

# 3) harnesses, linked with smtpd(8)'s objects
harness_env "$B/fuzz" "$FUZZ_CFLAGS" smtpd
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$B/lsan_off.o"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
for src in "$SRC"/mayhem/harnesses/fuzz_*.c; do
	name=$(basename "$src" .c)
	# shellcheck disable=SC2086
	(cd "$B/fuzz/mk/$PROG" && $CC $FUZZ_CFLAGS $CPPFLAGS_H -c "$src" -o "$B/$name.o")
	# shellcheck disable=SC2086
	$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$name.o" \
		"${OBJS_H[@]}" "$B/lsan_off.o" $LIBS_H -o "$OUT/$name"
	# shellcheck disable=SC2086
	$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$B/standalone_main.o" "$B/$name.o" \
		"${OBJS_H[@]}" "$B/lsan_off.o" $LIBS_H -o "$OUT/$name-standalone"
done

# 3b) the sendmail(8) target: enqueue.c behind a file-input main(), AFL++
#     (LeakSanitizer is already off through the afl build's LIBS)
harness_env "$B/afl" "$SANITIZER_FLAGS $DEBUG_FLAGS" smtpctl afl-clang-fast
# shellcheck disable=SC2086
(cd "$B/afl/mk/smtpctl" && AFL_QUIET=1 afl-clang-fast $SANITIZER_FLAGS $DEBUG_FLAGS $CPPFLAGS_H \
	"$SRC/mayhem/harnesses/sendmail_enqueue.c" "${OBJS_H[@]}" $LIBS_H -o "$OUT/sendmail-enqueue")

# 4) known-answer test, against the normally-built objects
harness_env "$B/normal" "-g -O2 $COVERAGE_FLAGS" smtpd
# shellcheck disable=SC2086
(cd "$B/normal/mk/smtpd" && $CC -g -O2 $COVERAGE_FLAGS $CPPFLAGS_H "$SRC/mayhem/selftest.c" \
	"${OBJS_H[@]}" $LIBS_H $COVERAGE_FLAGS -o "$OUT/selftest")
