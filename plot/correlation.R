# Generate the correlation heatmap for the variables selected for the
# empirical analysis.
Sys.setenv(LANG = "en")
Sys.setenv(TZ = "UTC")

library(dplyr)
library(ggplot2)
library(optparse)
library(this.path)
library(yaml)
library(tidyr)

setwd(this.path::here())
source("layout.R", chdir = TRUE)
create_save_locations()

opt <- parse_args(OptionParser(option_list = list(
  make_option("--model_conf",
              type = "character",
              default = "conf/model.yml",
              help = paste("Model configuration file"))
)))


#' Aggregate the package windows in the same way as the model, with one row per
#' repository and directory combination and release, and the covariates
#' averaged over the windows of the history.
#'
#' @param data the package windows.
#' @param variables the columns to keep.
#' @return one row per combination and release.
#'
aggregate_repository <- function(data, variables) {
  covariates <- setdiff(variables, "severe_osv")

  averaged <- data %>%
    group_by(release, combination) %>%
    summarise(across(all_of(covariates), ~ mean(.x, na.rm = TRUE)),
              .groups = "drop")

  targets <- data %>%
    group_by(release, combination) %>%
    summarise(severe_osv = max(severe_osv),
              .groups = "drop")

  aggregated <- left_join(averaged, targets, by = c("release", "combination"))
  aggregated
}

#' Plot the correlation heatmap of a set of package windows.
#'
#' @param data the package windows.
#' @param variables the columns to correlate, in the order of the axes.
#' @return the plot.
#'
corr_plot <- function(data, variables) {
  values <- data[, variables]
  corr <- cor(values[complete.cases(values), ], method = "spearman")

  columns <- colnames(corr)
  labels <- setNames(vapply(columns, label_of, ""), columns)

  long <- as.data.frame(corr) %>%
    mutate(var1 = rownames(.)) %>%
    pivot_longer(-var1, names_to = "var2", values_to = "correlation") %>%
    mutate(var1 = factor(var1, levels = columns),
           var2 = factor(var2, levels = columns)) %>%
    # Show only the lower triangle of the correlation matrix to avoid
    # repetitions.
    filter(as.integer(var1) < as.integer(var2))
  x_limits <- columns[-length(columns)]
  y_limits <- rev(columns[-1])

  p <- ggplot(long, aes(x = var1, y = var2, fill = correlation)) +
    geom_tile(colour = "white", linewidth = 0.3) +
    # The cell text and the axis labels use the tick size of the other
    # figures; geom_text takes millimetres, hence the conversion.
    geom_text(aes(label = sprintf("%.2f", correlation)),
              colour = "black", size = TINY.SIZE / ggplot2::.pt) +
    scale_x_discrete(limits = x_limits, labels = labels) +
    scale_y_discrete(limits = y_limits, labels = labels) +
    scale_fill_gradient2(low = COLOURS.LIST.DARK[2], mid = "white",
                         high = COLOURS.LIST.DARK[1], limits = c(-1, 1),
                         guide = "none") +
    labs(x = NULL, y = NULL) +
    theme_paper_base() +
    theme(axis.text = element_text(size = TINY.SIZE, colour = "black"),
          axis.text.x = element_text(size = TINY.SIZE, angle = 30,
                                     hjust = 1, vjust = 1, colour = "black"))

  p
}


# Select the variables to calculate correlations for.
inputs <- model_inputs(opt$model_conf)
variables <- c("project_age", "commits", inputs$features, "severe_osv")

# Load data.
data <- read_metrics(inputs)
releases <- levels(data$release)

# Determine target.
if (all(c("critical_osv_count", "high_osv_count") %in% names(data))) {
  data$severe_osv <- as.integer(
    data$critical_osv_count + data$high_osv_count > 0
  )
}

# Select unique combinations of release, repositories, directories and windows.
data <- data %>%
  group_by(release, combination, window) %>%
  slice_head(n = 1) %>%
  ungroup()
aggregated <- aggregate_repository(data, variables)

# Create and store plot.
save_plot(
  corr_plot(aggregated, variables),
  "corr_spearman",
  width = COLWIDTH,
  height = 0.47 * COLWIDTH
)
