# Plot the model coefficients.
Sys.setenv(LANG = "en")
Sys.setenv(TZ = "UTC")

library(dplyr)
library(tidyr)
library(ggplot2)
library(optparse)
library(this.path)

setwd(this.path::here())
source("layout.R", chdir = TRUE)
create_save_locations()

opt <- parse_args(OptionParser(option_list = list(
  make_option("--model_conf", type = "character",
              default = "conf/model.yml",
              help = paste("Model configuration file"))
)))

fits <- c(multi = "Multivariate", uni = "Univariate")
row_offsets <- setNames(c(0, -0.3), fits)
fit_colours <- setNames(COLOURS.LIST.DARK[c(1, 2)], fits)
#' Label the given column or release names.
#'
#' @param names the column or release names.
#' @return the labels.
#'
labels_of <- function(names) vapply(names, label_of, "")

#' Move the per-release coefficients of one fit into a long table.
#'
#' @param coefficients the coefficient table the fit wrote.
#' @param prefix the start of the per-release columns of one fit.
#' @param fit the name of the fit.
#' @return one row per feature and release.
#'
release_long <- function(coefficients, prefix, fit) {
  columns <- grep(prefix, names(coefficients), value = TRUE)
  coefficients %>%
    select(all_of(c("label", columns))) %>%
    tidyr::pivot_longer(all_of(columns), names_to = "release",
                        values_to = "coefficient") %>%
    mutate(release = labels_of(sub(prefix, "", release)), fit = fit)
}

#' Place a mark on the row of its metric, shifted by its fit.
#'
#' @param coefficients the coefficient table, with the labels as a factor.
#' @param label the metric labels.
#' @param fit the fits.
#' @return the y position of every mark.
#'
row_of <- function(coefficients, label, fit) {
  match(as.character(label), levels(coefficients$label)) + row_offsets[fit]
}

# Load data.
inputs <- model_inputs(opt$model_conf)

coefficients <- read.csv(inputs$coefficients, stringsAsFactors = FALSE)
coefficients$label <- labels_of(coefficients$feature)
coefficients$label <- factor(coefficients$label,
                             levels = rev(coefficients$label))

# Combine coefficients into a joint table for plotting.
estimates <- bind_rows(
  coefficients %>%
    transmute(label, fit = fits[["uni"]], coefficient = uni,
              ci_low = uni_ci_low, ci_high = uni_ci_high),
  coefficients %>%
    select(label, coefficient, ci_low, ci_high) %>%
    mutate(fit = fits[["multi"]])
) %>%
  mutate(fit = factor(fit, levels = fits))

# Create a long table of the per-release coefficients of both fits.
per_release <- bind_rows(
  release_long(coefficients, "^uni_release_", fits[["uni"]]),
  release_long(coefficients, "^release_", fits[["multi"]]))
per_release$fit <- factor(per_release$fit, levels = fits)

pooled <- "All releases"
shapes <- c(18, 1, 0, 2)
names(shapes) <- c(pooled, unique(as.character(per_release$release)))

estimates$row <- row_of(coefficients, estimates$label, estimates$fit)
per_release$row <- row_of(coefficients, per_release$label, per_release$fit)

# Create and store the coefficient plot.
p <- ggplot(estimates, aes(x = coefficient, y = row, colour = fit)) +
  geom_vline(xintercept = 0, colour = COLOURS.LIST.DARK[2],
             linewidth = LINE.SIZE.THIN) +
  # Add caps to mark where a bootstrap interval ends.
  geom_errorbarh(aes(xmin = ci_low, xmax = ci_high), height = 0.18,
                 linewidth = LINE.SIZE.THIN) +
  # Add per-release coefficients as hollow marks.
  geom_point(data = per_release,
             aes(x = coefficient, y = row, colour = fit, shape = release),
             size = BIG.POINT.SIZE * 1.4, stroke = 0.35) +
  # Add the pooled estimate as a filled mark.
  geom_point(aes(shape = pooled), size = BIG.POINT.SIZE * 2.6) +
  scale_y_continuous(breaks = seq_along(levels(coefficients$label)),
                     labels = levels(coefficients$label),
                     expand = expansion(add = c(0.4, 0.35))) +
  scale_colour_manual(values = fit_colours, name = NULL) +
  scale_shape_manual(values = shapes, breaks = names(shapes), name = NULL) +
  guides(colour = guide_legend(order = 1, override.aes = list(shape = 18)),
         shape = guide_legend(order = 2,
                              override.aes = list(colour = "black"))) +
  labs(x = "Standardised regression coefficient", y = NULL) +
  theme_paper_base() +
  theme(axis.title.y = element_blank(),
        axis.text = element_text(size = SMALL.SIZE),
        axis.title.x = element_text(size = SMALL.SIZE),
        legend.text = element_text(size = TINY.SIZE),
        legend.key.size = unit(0.5 * SYM.SIZE, "line"),
        panel.grid.major.y = element_blank(),
        panel.grid.minor.y = element_blank(),
        legend.box = "vertical",
        legend.box.spacing = unit(2, "pt"),
        legend.spacing.y = unit(0, "pt"),
        # Add small margins for the legend and ticks labels.
        plot.margin = unit(c(0.12, 0.15, 0, 0.1), "cm")) +
  shrink_legend()

save_plot(p, paste0(inputs$name, "_coefficients"), width = COLWIDTH,
          height = 0.19 * nrow(coefficients) + 0.75)