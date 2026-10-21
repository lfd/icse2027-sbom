SA=sbom-analysis -v
IMAGE=sbom-analysis:full

# Short names for releases to analyse.
BULLSEYE=debian-bullseye-20210816
BOOKWORM=debian-bookworm-20230612
TRIXIE=debian-trixie-20250811
RELEASES=$(BULLSEYE) $(BOOKWORM) $(TRIXIE)

# Output directories for analysis and model files.
O_ANALYSIS=data/analysis
O_MODEL=data/model

# Output files for the analysis.
CONFS=$(foreach r,$(RELEASES),conf/$(r).yml)
METRICS=$(foreach r,$(RELEASES),$(O_ANALYSIS)/$(r)/metrics.csv)

# Models to be fitted and used for annotation.
MODEL_ALL=$(O_MODEL)/attention-score.json
MODEL_BOOKWORM=$(O_MODEL)/attention-score-bookworm.json
MODEL_TRIXIE=$(O_MODEL)/attention-score-trixie.json
MODELS=$(MODEL_ALL) $(MODEL_BOOKWORM) $(MODEL_TRIXIE)

# Instead of automatically running dependencies, print a message if they do
# not exist.
require=@for f in $(1); do test -f $$f || { echo "Missing $$f: run 'make $(2)' first." >&2; exit 1; }; done

.PHONY: repro repro_docker config extract analyse fit annotate plot

.DEFAULT_GOAL=plot

config:
	for r in $(RELEASES); do $(SA) setup-config sbom/$$r.spdx.json conf/$$r.yml || exit 1; done

extract:
	$(call require,$(CONFS),config)
	for c in $(CONFS); do $(SA) extract $$c || exit 1; done

analyse:
	$(call require,$(CONFS),config)
	for c in $(CONFS); do $(SA) analyse $$c || exit 1; done

fit:
	$(call require,$(METRICS),analyse)
	$(SA) fit conf/model.yml
	$(SA) fit conf/model_bookworm.yml
	$(SA) fit conf/model_trixie.yml

annotate:
	$(call require,$(MODELS),fit)
	$(SA) annotate --model_file $(MODEL_ALL) conf/$(BULLSEYE).yml sbom/$(BULLSEYE).graphml
	$(SA) annotate --previous_conf_file conf/$(BULLSEYE).yml --published_before 2023-06-12 conf/$(BOOKWORM).yml sbom/$(BOOKWORM).graphml
	$(SA) annotate --model_file $(MODEL_BOOKWORM) conf/$(BOOKWORM).yml sbom/$(BOOKWORM).graphml
	$(SA) annotate --previous_conf_file conf/$(BOOKWORM).yml --published_before 2025-08-11 conf/$(TRIXIE).yml sbom/$(TRIXIE).graphml
	$(SA) annotate --model_file $(MODEL_TRIXIE) conf/$(TRIXIE).yml sbom/$(TRIXIE).graphml

plot:
	bash plot/pipeline.sh

repro:
	$(MAKE) config
	$(MAKE) extract
	$(MAKE) analyse
	$(MAKE) fit
	$(MAKE) annotate
	$(MAKE) plot

repro_docker:
	docker build --target full -t $(IMAGE) .
	docker run --rm -it -v "$(CURDIR):/work" -w /work \
		-u "$$(id -u):$$(id -g)" -e HOME=/tmp $(IMAGE) make repro
