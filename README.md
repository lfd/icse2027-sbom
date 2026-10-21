# Reproduction package for "Beyond a Bill: Tracing, Mining and Assessing Packages in the Debian Ecosystem"

This study proposes and evaluates an SBOM analysis tool for the Debian 
ecosystem. The tool
traces packages to their packaging and project repositories, mines and fuses
their development history and code, and annotates the SBOM dependency graph
with maintenance and quality indicators. Across three Debian releases, we
analyse these indicators and combine them into a package attention score to
prioritise packages for quality assurance review.

A full reproduction package with the analysis data and the exported Docker
image is available at [Zenodo](https://zenodo.org/records/23502496?preview=1&token=eyJhbGciOiJIUzUxMiIsImlhdCI6MTc5MjUxMDEzMCwiZXhwIjoxODYxODMzNTk5fQ.eyJpZCI6IjhjNzAzMGFmLTc3YWYtNDNjYi05N2JhLTE3YTkyNWQ2NDE5MSIsImRhdGEiOnt9LCJyYW5kb20iOiJlNGE4OTc5OWRhYzljOGE2ZDhlOWUzZTczOWE0ODMxOCJ9.zQ_LZ9aJluUXvyD-bfT6TrU0Q0WZz073MxVsUYiKeaT_LZ98ZMqNTZssE2Qjn99P4zNLcXVC9up9SmjFRXxQYA).

## Repository contents

- `src/`: the `sbom-analysis` tool, which traces SBOM packages to their
  repositories, mines them, calculates metrics, fits the attention score and
  annotates the dependency graph.
- `sbom/`: the SBOMs and dependency graphs of the three Debian 
  releases, together with the script which generated them using 
  [debsbom](https://github.com/siemens/debsbom).
- `conf/`: the model configurations; analysis configurations for the SBOMs
  will be created by the pipeline.
- `data/`: the cloned repositories, extracted histories, metrics and fitted
  models, created by the pipeline.
- `plot/`: the R scripts for the figures and tables of the paper.
- `docs/`: the documentation of the tool usage and the metrics.

## Setup

### Prerequisites

Please ensure that [Docker](https://docs.docker.com/get-docker/) and
[GNU Make](https://www.gnu.org/software/make/) are installed on your system.

### 1. Clone the repository

```
git clone <repository-url>
```

### 2. Reproduce the results

```
make repro_docker
```

This builds the Docker image and runs the full pipeline inside a container:
The pipeline sets up the analysis configuration of each release by tracing the
packaging and project repositories. It clones the repositories, matches
the package versions and extracts their histories. From these, it calculates
the metrics and queries known vulnerabilities, fits the attention score and
annotates the SBOM graphs. Finally, it generates the figures and tables of the
paper.

As the full pipeline clones and analyses several hundred repositories, it may 
take several hours to finish.

> [!NOTE]
> The pipeline depends on several online resources. For instance, scraped
> websites, the repositories and the OSV database change over time, so a rerun
> may lead to results which differ from those presented in the paper.
> 
> Therefore, our reproduction package on [Zenodo](https://zenodo.org/records/23502496?preview=1&token=eyJhbGciOiJIUzUxMiIsImlhdCI6MTc5MjUxMDEzMCwiZXhwIjoxODYxODMzNTk5fQ.eyJpZCI6IjhjNzAzMGFmLTc3YWYtNDNjYi05N2JhLTE3YTkyNWQ2NDE5MSIsImRhdGEiOnt9LCJyYW5kb20iOiJlNGE4OTc5OWRhYzljOGE2ZDhlOWUzZTczOWE0ODMxOCJ9.zQ_LZ9aJluUXvyD-bfT6TrU0Q0WZz073MxVsUYiKeaT_LZ98ZMqNTZssE2Qjn99P4zNLcXVC9up9SmjFRXxQYA) 
> contains the
> analysis data and the generated figures and tables as presented in the paper.
> For quickly evaluating the pipeline, you can rerun specific targets from this
> data with `make fit`, `make annotate` or `make plot` in the development
> environment as described below.

### 3. Development environment (optional)

For an interactive shell in the analysis environment:

```
docker build --target full -t sbom-analysis:full .
docker run --rm -it -v "$PWD:/work" -w /work sbom-analysis:full bash
```

The analysis CLI is available as `sbom-analysis`:

```
usage: sbom-analysis [-h] {setup-config, extract, analyse, fit, annotate}

SBOM analysis for risk assessment.

positional arguments:
  {setup-config, extract, analyse, fit, annotate}
                      sub command help
    setup-config      create the initial analysis configuration from an SBOM
    extract           extract history from the package git repositories
    analyse           analyse the extracted data and calculate metrics
    fit               fit a package attention score on the calculated metrics
    annotate          annotate an existing dependency graph

options:
  -h, --help          show this help message and exit
```

See [`docs/metrics.md`](docs/metrics.md) for the offered metrics and
[`docs/usage.md`](docs/usage.md) for the steps of an analysis.
