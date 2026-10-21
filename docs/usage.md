# Tool usage

1. Prerequisite: The tool takes as input an SBOM in SPDX format and optionally
a dependency graph in GraphML format. Please generate these for your system,
for instance using [debsbom](https://github.com/siemens/debsbom) or
[syft](https://github.com/anchore/syft).
For testing purposes, you can use the example files in the ```./sbom``` folder.

2. Create a configuration file from the SBOM file using the `setup-config`
command. This will retrieve the downstream and upstream repository URLs for
each package, if possible.
    ```
    usage: sbom-analysis setup-config [-h] sbom_file conf_file
    
    positional arguments:
      sbom_file   SBOM file to process
      conf_file   Configuration file path
    ```
   
3. Please manually adjust local paths, parallelisation and desired metrics in
the configuration
file. By default, all metrics except the static analysis metrics from
[cppcheck](https://cppcheck.sourceforge.io/) are enabled, including the
computationally more expensive code metrics from
[lizard](https://github.com/terryyin/lizard) (see [Metrics](metrics.md#metrics)).
To enable the cppcheck metrics as well, uncomment them in the default
`metrics` list in
[config.py](../src/sbom_analysis/config/config.py).

4. Extract the required data from the repositories using the `extract` command.
Data from a repository is only extracted if a (heuristically) matching version
could be identified (e.g. by branch, tag or commit message). This prevents a
mismatch between the actual package version and the repository data, which
would lead to incorrect metrics and misinterpretation.
    ```
    usage: sbom-analysis extract [-h] conf_file
   
    positional arguments:
      conf_file   Configuration file to process
    ```

5. Calculate metrics using the `analyse` command. This may take a while
depending on the configured metrics and related analyses.
   ```
   usage: sbom-analysis analyse [-h] conf_file

   positional arguments:
     conf_file   Configuration file to process
   ```
The calculated metrics can be found in the `analysis_dir` specified in the
configuration file.

By default, the repositories are analysed sequentially in one process.
For parallel analysis, which is recommended for large-scale code analyses,
set `jobs` in the configuration file to the desired number of CPU cores or to
-1 for all cores. Note that code analysis tools may exhaust the available
memory if too many run at the same time.

6. Optionally, fit a package attention score on the calculated metrics using
the `fit` command. The score is a logistic regression which relates selected
maintenance and quality metrics of a package defined in `conf/model.yml` to
whether the version contains severe vulnerabilities. It is meant to draw a 
reviewers attention towards packages worth looking at first, not to predict
vulnerabilities.
   ```
   usage: sbom-analysis fit [-h] model_conf_file

   positional arguments:
     model_conf_file  Model configuration file to process
   ```
The fitted model, coefficients and data are stored in the `model_dir`.
To evaluate a model on a later release, set `published_before` in the model
configuration to the date of that release, so that only vulnerabilities known
at that time are counted.

7. Annotate the dependency graph with the calculated metrics using the
`annotate` command. Only the latest calculated metrics will be added as node
attributes for readability. Every package is assigned an attention level. By
default, the level is derived from the size of the package and the presence of
severe vulnerabilities in the previous release, if available. Optionally, the
model fitted by the `fit` command assigns the levels.
   ```
   usage: sbom-analysis annotate [-h] [--model_file MODEL_FILE]
                                 [--previous_conf_file PREVIOUS_CONF_FILE]
                                 [--published_before PUBLISHED_BEFORE]
                                 conf_file graph_file
   
   positional arguments:
     conf_file   Configuration file to process
     graph_file  SBOM graphml file to annotate

   options:
     --model_file MODEL_FILE
                 Fitted model file to process
     --previous_conf_file PREVIOUS_CONF_FILE
                 Configuration file of the previous release
     --published_before PUBLISHED_BEFORE
                 Only consider vulnerabilities of the previous release
                 published before this date (YYYY-MM-DD), e.g. the release
                 date of the packages to rank
   ```
The annotated graph can be found in the `analysis_dir` specified in the
configuration file, with its colours indicating the attention level of each 
package:
- **red**: Packages with known severe vulnerabilities.
- **orange**, **yellow**, **pale yellow**: Packages without a known severe
vulnerability, but scored with an attention level: `high`,
`elevated` and `low`, assigned either by default rules (packages vulnerable in
the previous release, if available, and the largest packages) or by a fitted
attention score model (see the `annotate` command).
- **white**: Packages for which no repository could be identified, no data
could be extracted, or the scoring failed due to missing metrics.

## Limitations

- The tool currently only supports SBOMs in SPDX format and dependency graphs
in GraphML format.
- If neither an external reference or a homepage is specified in the SBOM, or
the URL is misleading, a package cannot be reliably analysed. A static package
mapping, heuristics and scraping helpers are implemented for Debian systems, 
but they cannot guarantee correctness for unseen packages.
- We limit static analyses to the latest snapshot of the repository in the
given time window for performance reasons. Therefore, code metrics should be
interpreted as approximate values.
