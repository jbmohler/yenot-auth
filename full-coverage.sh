#!in/sh

if [ -z "$YENOT_PORT" ]; then
	export YENOT_PORT=18018
fi
if [ -z "$YENOT_DB_URL" ]; then
	export YENOT_DB_URL=postgresql:///my_coverage_test
fi
export INIT_DB_PASSWD=123admin-test123

rm -rf .coverage
rm -rf .coverage.*
rm -rf htmlcov

COVERAGE_PROCESS_START=.coveragerc python -c "import yenot"

if ls .coverage.* 1> /dev/null 2>&1; then
	rm -rf .coverage.*
	echo "coverage auto-starting installed correctly"
else
	echo "See https://coverage.readthedocs.io/en/v4.5.x/subprocess.html"
	echo "to properly configure coverage for this script.  Consider "
	echo "echo \"import coverage; coverage.process_startup()\" >" `python -c "import bottle; import os; print(os.path.dirname(bottle.__file__))"`/coverage_startup.pth
	exit
fi

COVERAGE_PROCESS_START=.coveragerc pytest tests
COVERAGE_PROCESS_START=.coveragerc python tests/end-to-end.py
coverage combine
coverage report
if [ ]; then
	coverage html
	xdg-open htmlcov/index.html &>/dev/null
fi
