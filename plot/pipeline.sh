#! /bin/bash

# Build figures and tables based on the analysed data.

cd "$(dirname "$0")"

# Describe release characteristics.
Rscript release_stats.R

# Summarise how the repository URLs of the package mapping were resolved.
Rscript mapping_stats.R

# Summarise and visualise metric distributions over the package windows.
Rscript metric_summary.R
Rscript metric_facets.R

# Calculate correlations between the model and context metrics.
Rscript correlation.R

# Visualise model coefficients and their confidence intervals.
Rscript model_coefficients.R

# Compare the package attention score performance from the model and the
# rule-based default.
Rscript model_ranking.R

# Plot an example from the annotated network graph.
Rscript network.R

echo
echo "LaTeX sources in tex/ and tab/"
echo "Figures and tables for manual inspection in pdf/ and csv/"
