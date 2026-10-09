.PHONY: run test stage

run:
	.venv/bin/python -m ad_housekeeping

test:
	.venv/bin/python -m unittest discover -s tests -v

stage:
	.venv/bin/python -c "from ad_housekeeping.web import stage_bundle; print(stage_bundle())"
