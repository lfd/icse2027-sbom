# Generate the metrics distribution facet plots for selected metrics
# across releases.
Sys.setenv(LANG = "en")
Sys.setenv(TZ = "UTC")

library(dplyr)
library(ggplot2)
library(ggh4x)
library(optparse)
library(this.path)
library(yaml)

setwd(this.path::here())
source("layout.R", chdir = TRUE)
create_save_locations()

opt <- parse_args(OptionParser(option_list = list(
  make_option("--model_conf", type = "character",
              default = "conf/model.yml",
              help = "Model configuration file")
)))

# The bins and labels of every feature.
bins <- list(
  commits = list(
    breaks = c(-1, 0, 10, 50, 200, 1000, Inf),
    labels = c("0", "1-10", "11-50", "51-200", "201-1k", ">1k")),
  developers = list(
    breaks = c(-1, 0, 1, 5, 10, 50, Inf),
    labels = c("0", "1", "2-5", "6-10", "11-50", ">50")),
  churn_per_function = list(
    breaks = c(-1, 0, 1, 10, 50, 200, Inf),
    labels = c("0", "0-1", "1-10", "10-50", "50-200", ">200")),
  corrective_ratio = list(
    breaks = c(-1, 0, 0.05, 0.1, 0.2, 0.3, 0.5, Inf),
    labels = c("0.00", "0.00-0.05", "0.05-0.10", "0.10-0.20", "0.20-0.30",
               "0.30-0.50", ">0.50")),
  pony_factor = list(
    breaks = c(-1, 0, 1, 2, 5, Inf),
    labels = c("0", "1", "2", "3-5", ">5")),
  newcomer_ratio = list(
    breaks = c(-1, 0, 0.25, 0.5, 0.75, 1 - 1e-9, Inf),
    labels = c("0.00", "0.00-0.25", "0.25-0.50", "0.50-0.75", "0.75-1.00",
               "1.00")),
  loc = list(
    breaks = c(-1, 999, 9999, 49999, 99999, 499999, Inf),
    labels = c("<1k", "1k-10k", "10k-50k", "50k-100k", "100k-500k", ">500k")),
  cyclomatic_complexity_per_function = list(
    breaks = c(0, 2, 4, 6, 8, 10, 15, Inf),
    labels = c("1-2", "2-4", "4-6", "6-8", "8-10", "10-15", ">15"))
)
# The bins of the panels are told apart by a prefix which the axis hides, as
# panels share labels such as "1-10" in different positions.
sep <- "\u001f"

#' Count the package windows of every release per bin of several features.
#'
#' @param windows the package windows.
#' @param features the features to bin, in the order of the panels.
#' @return one row per panel, release and bin, with the share of windows.
#'
facet_counts <- function(windows, features) {
  counts <- bind_rows(lapply(features, function(feature) {
    windows %>%
      filter(!is.na(.data[[feature]])) %>%
      mutate(bin = cut(.data[[feature]], bins[[feature]]$breaks,
                       labels = bins[[feature]]$labels)) %>%
      count(release, bin, .drop = FALSE) %>%
      group_by(release) %>%
      mutate(share = n / sum(n)) %>%
      ungroup() %>%
      mutate(panel = label_of(feature), bin = paste(panel, bin, sep = sep))
  }))
  counts$bin <- factor(counts$bin, levels = unlist(lapply(features, function(f) {
    paste(label_of(f), bins[[f]]$labels, sep = sep)
  })))
  counts$panel <- factor(counts$panel, levels = vapply(features, label_of, ""))
  counts
}

#' Draw the facet plot of binned shares.
#'
#' @param counts the shares as facet_counts() returned them.
#' @param nrow the number of rows of panels.
#' @return the plot.
#'
facet_plot <- function(counts, nrow) {
  ggplot(counts, aes(x = bin, y = share, fill = release)) +
    geom_col(position = position_dodge(width = 0.75), width = 0.68) +
    labs(x = NULL, y = "Share of time windows", fill = NULL) +
    scale_x_discrete(labels = function(x) sub(paste0("^.*", sep), "", x)) +
    scale_y_continuous(labels = function(x) sprintf("%.2f", x),
                       expand = expansion(mult = c(0, 0.05))) +
    scale_fill_manual(values = release_colours(levels(counts$release))) +
    facet_wrap2(~ panel, scales = "free", nrow = nrow, dir = "v",
                axes = "all") +
    theme_paper_base() +
    theme(axis.text = element_text(size = TINY.SIZE),
          # Rotate the ratio bins on the x-axis.
          axis.text.x = element_text(size = TINY.SIZE, angle = 45, hjust = 1),
          axis.title.y = element_text(size = SMALL.SIZE),
          strip.text = element_text(size = SMALL.SIZE),
          # In the legend, center the text to the colour box.
          legend.text = element_text(size = SMALL.SIZE, vjust = 0.5),
          legend.key.size = unit(0.6 * SYM.SIZE, "line"),
          legend.key.spacing.x = unit(4, "pt"),
          # Add space for the legend.
          plot.margin = unit(c(0.15, 0.15, 0, 0.1), "cm")) +
    shrink_legend()
}

inputs <- model_inputs(opt$model_conf)
windows <- read_metrics(inputs)

# Plot developer base distributions.
save_plot(facet_plot(facet_counts(windows, c("pony_factor", "newcomer_ratio")),
                     nrow = 1),
          "metric_facets", width = COLWIDTH, height = 0.4 * COLWIDTH)
