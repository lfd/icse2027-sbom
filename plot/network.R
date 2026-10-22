# Plot an example network visualising the interactive graph.
Sys.setenv(LANG = "en")
Sys.setenv(TZ = "UTC")

library(cowplot)
library(ggnetwork)
library(ggplot2)
library(igraph)
library(grid)
library(this.path)
library(xml2)

setwd(this.path::here())
source("layout.R", chdir = TRUE)
create_save_locations()

# Selected package for which the annotation is drawn.
ANNOTATED <- "openssl"
# Metrics the annotation box lists, in the respective order.
ANNOTATE.METRICS <- c("attention_score", "version", "upstream_repo",
                      "downstream_repo", "commits",
                      "developers", "newcomer_ratio", "pony_factor",
                      "corrective_ratio",
                      "cyclomatic_complexity_per_function", "loc",
                      "severe_osv_count")
# Number of hops the neighbourhood panel shows and how many the frame in the
# graph encloses.
ZOOM.ORDER <- 2
REGION.ORDER <- 1
# The seed which makes the layout repeatable.
SEED <- 42
# How strongly the packages repel each other in the layout.
CHARGE <- 0.02
# Shape of the graph.
ASPECT <- 2.2
PULL.IN <- 0.75
SPREAD <- 0.4
NODE.GAP <- 0.125
# How far an arrow stops from the package it points at.
ARROW.GAP <- 0.062

# Two-column layout. The height follows from the content, see
# figure_height().
FIGURE.WIDTH <- TEXTWIDTH
FIGURE.HEIGHT <- 0.35 * TEXTWIDTH
# Width of the release graph, as a share of the figure width.
GRAPH.PANEL <- 0.575
# Vertical gaps in inches: below and above the step titles, between the
# window frame and the panels, and the top bar of the window.
GAPS <- c(bottom = 0.02, steps = 0.11, between = 0.05, frame = 0.05,
          bar = 0.17, top = 0.005)
# Line height and padding in points of the metrics box.
BOX.LINE.HEIGHT <- 1.05
BOX.PADDING <- 24

# The annotated GraphML file based on which to draw the graph.
GRAPH <- file.path("..", "data", "analysis", "debian-trixie-20250811",
                   "graph_annotated_attention-score-trixie.graphml")
RELEASE <- "Trixie"
# The website with the interactive graphs, linked in the figure.
WEBSITE <- "lfd.github.io/icse2027-sbom.github.io"

# Colour meanings, i.e. how much attention a reviewer should draw to the
# respective package.
LEVELS <- c("not analysed", "low", "elevated", "high", "vulnerable")
# The corner radius of the framed panels.
CORNER.RADIUS <- 3
# The padding of the graph panel, as a fraction of its data range.
GRAPH.EXPAND <- 0.06
# The range the packages are drawn at, smallest to largest.
GRAPH.SIZES <- c(1.5, 4.6)
ZOOM.SIZES <- c(2.2, 4.0)
# The padding of the zoom panel, as a fraction of its data range.
ZOOM.EXPAND.X <- c(0.22, 0.30)
ZOOM.EXPAND.Y <- c(0.13, 0.13)
# The corporate yellow in its three strengths, as the interactive graph uses
# them, and the red for a confirmed vulnerability.
LEVEL.COLOURS <- c("not analysed" = "white",
                   "low" = COLOURS.LIST.LIGHT[1],
                   "elevated" = COLOURS.LIST.MEDIUM[1],
                   "high" = COLOURS.LIST.DARK[1],
                   "vulnerable" = COLOURS.LIST.DARK[5])

#' Read an annotated graph written by networkx.
#'
#' @param file the graph file.
#' @return a list of the nodes and the edges.
#'
read_annotated_graph <- function(file) {
  doc <- read_xml(file)
  ns <- c(g = xml_ns(doc)[[1]])

  keys <- xml_find_all(doc, "//g:key", ns)
  key_name <- setNames(xml_attr(keys, "attr.name"), xml_attr(keys, "id"))

  #' Collects the data elements of one node or edge, keeping the first value
  #' which a key of a given name carries.
  values_of <- function(element) {
    data <- xml_find_all(element, "g:data", ns)
    values <- xml_text(data)
    names(values) <- key_name[xml_attr(data, "key")]
    values <- values[values != "" & values != "nan" & !is.na(names(values))]
    values[!duplicated(names(values))]
  }

  #' Turns a list of named value vectors into a data frame, filling in the
  #' attributes which an entry does not carry.
  as_table <- function(elements, extra) {
    rows <- lapply(elements, values_of)
    columns <- unique(c(extra, unlist(lapply(rows, names))))
    frame <- as.data.frame(
      do.call(rbind, lapply(rows, function(row) row[columns])),
      stringsAsFactors = FALSE)
    names(frame) <- columns
    frame
  }

  node_elements <- xml_find_all(doc, "//g:node", ns)
  nodes <- as_table(node_elements, "name")
  nodes$id <- xml_attr(node_elements, "id")

  edge_elements <- xml_find_all(doc, "//g:edge", ns)
  edges <- data.frame(from = xml_attr(edge_elements, "source"),
                      to = xml_attr(edge_elements, "target"),
                      stringsAsFactors = FALSE)
  edges$reltype <- as_table(edge_elements, "reltype")$reltype

  # SPDX carries "generates" and its inverse "generated_from", and an SBOM may
  # use either. The two state the same link, so an SBOM which uses both would
  # draw one relation in two directions: the rust source packages point at the
  # binary they were built into, while pcre points the other way. The inverse
  # is turned around here, so that a source package always points at what it
  # generates.
  inverse <- !is.na(edges$reltype) & edges$reltype == "generated_from"
  edges[inverse, c("from", "to")] <- edges[inverse, c("to", "from")]
  edges$reltype[inverse] <- "generates"

  list(nodes = nodes, edges = edges)
}

#' Lay the graph out. The graphopt layout lets every package repel every
#' other, which spreads the many packages around the hubs instead of piling
#' them up in the middle as Kamada-Kawai and Fruchterman-Reingold do here.
#'
#' @param g the graph.
#' @return the coordinates.
#'
layout_of <- function(g) {
  igraph::layout_with_graphopt(g, niter = 1500, charge = CHARGE)
}

#' Move packages apart until none of them covers another.
#'
#' Spreading by distance from the middle says nothing about how large a
#' package is drawn, so two hubs can still end up on top of each other. This
#' pushes any overlapping pair apart along the line between them, repeatedly,
#' until every pair is clear. The graph keeps its shape: the pairs which do
#' not overlap are never touched.
#'
#' @param layout the coordinates, already at the shape they are drawn in.
#' @param degree the degree of each package, which sets how large it is drawn.
#' @param sizes the range the packages are drawn at.
#' @param gap the distance two of the largest packages must keep, in units of
#'   the layout; 0 leaves the layout alone.
#' @param rounds how many passes to make before giving up.
#' @return the coordinates.
#'
separate_nodes <- function(layout, degree, sizes, gap, rounds = 400) {
  if (gap <= 0) {
    return(layout)
  }
  # ggplot maps a size to the area of the point, so the drawn diameter grows
  # with the square root of the degree.
  span <- range(degree, na.rm = TRUE)
  fraction <- if (diff(span) > 0) {
    sqrt((degree - span[1]) / diff(span))
  } else {
    rep(1, length(degree))
  }
  radius <- gap / 2 * (sizes[1] + (sizes[2] - sizes[1]) * fraction) / sizes[2]
  needed <- outer(radius, radius, "+")

  for (round in seq_len(rounds)) {
    distances <- as.matrix(stats::dist(layout))
    diag(distances) <- Inf
    close <- which(distances < needed, arr.ind = TRUE)
    close <- close[close[, 1] < close[, 2], , drop = FALSE]
    if (nrow(close) == 0) {
      break
    }
    for (k in seq_len(nrow(close))) {
      i <- close[k, 1]
      j <- close[k, 2]
      delta <- layout[j, ] - layout[i, ]
      distance <- sqrt(sum(delta^2))
      if (distance < 1e-9) {
        # Two packages in the same spot have no line to move along.
        delta <- c(cos(k), sin(k)) * 1e-3
        distance <- sqrt(sum(delta^2))
      }
      step <- delta / distance * (needed[i, j] - distance) / 2
      layout[i, ] <- layout[i, ] - step
      layout[j, ] <- layout[j, ] + step
    }
    # Pushing the packages apart grows the layout, and the height is set back
    # to one at the end. That shrinks every distance again, so it is done here
    # instead, inside the loop, where the next round can answer for it.
    layout <- layout / diff(range(layout[, 2]))
  }
  layout
}

#' Pull the packages which sit furthest out back towards the middle.
#'
#' A layout leaves a handful of packages far outside the rest, and the edges
#' to them stretch across the panel while the graph itself is squeezed into a
#' corner of it. Everything beyond the ninth decile of the distance from the
#' middle keeps its direction and its order, but the room it is given beyond
#' that decile is reduced.
#'
#' @param layout the coordinates.
#' @param strength how much of that room to take away, 0 leaves the layout as
#'   it is and 1 puts every outlier on the decile itself.
#' @return the coordinates.
#'
pull_in_layout <- function(layout, strength) {
  if (strength <= 0) {
    return(layout)
  }
  centre <- colMeans(layout)
  centred <- sweep(layout, 2, centre)
  radius <- sqrt(rowSums(centred^2))
  edge <- stats::quantile(radius, 0.9, names = FALSE)
  target <- ifelse(radius > edge,
                   edge + (radius - edge) * (1 - strength),
                   radius)
  factors <- ifelse(radius > 0, target / radius, 1)
  sweep(centred * factors, 2, -centre)
}

#' Push the packages apart, away from the middle of the layout.
#'
#' A force-directed layout of a graph with a few large hubs piles most of its
#' packages up around the centre, where they overlap and hide the colour they
#' carry. Every package keeps the direction the layout gave it, but its
#' distance from the middle is moved towards the rank of that distance, which
#' spreads the packages evenly over the disc.
#'
#' @param layout the coordinates.
#' @param strength how far to move, 0 leaves the layout as it is and 1 spreads
#'   it evenly.
#' @return the coordinates.
#'
spread_layout <- function(layout, strength) {
  if (strength <= 0) {
    return(layout)
  }
  centre <- colMeans(layout)
  centred <- sweep(layout, 2, centre)
  radius <- sqrt(rowSums(centred^2))
  ranked <- sqrt(rank(radius, ties.method = "first") / length(radius)) *
    max(radius)
  target <- (1 - strength) * radius + strength * ranked
  # A package which sits exactly in the middle has no direction to move in.
  factors <- ifelse(radius > 0, target / radius, 1)
  sweep(centred * factors, 2, -centre)
}

#' Lay out the graph of one release.
#'
#' @param file the annotated graph.
#' @param release the release the graph belongs to.
#' @return the nodes and edges in the coordinates of the layout.
#'
build_net <- function(file, release) {
  graph <- read_annotated_graph(file)
  nodes <- graph$nodes
  edges <- graph$edges

  # Consider vulnerabilities ranked high and critical as severe.
  critical <- suppressWarnings(as.numeric(nodes$critical_osv_count))
  high <- suppressWarnings(as.numeric(nodes$high_osv_count))
  nodes$severe_osv_count <- ifelse(is.na(critical) & is.na(high), NA,
                                   rowSums(cbind(critical, high),
                                           na.rm = TRUE))

  # Assign Debian vulnerabilities, which the OSV database reports for source
  # packages only, also to binary packages.
  attributed <- if ("severe" %in% names(nodes)) nodes$severe else NA
  severe <- rowSums(cbind(nodes$severe_osv_count,
                          suppressWarnings(as.numeric(attributed))),
                    na.rm = TRUE)
  level <- if ("attention_level" %in% names(nodes)) {
    nodes$attention_level
  } else {
    rep(NA_character_, nrow(nodes))
  }
  nodes$level <- factor(
    ifelse(severe > 0, "vulnerable",
           ifelse(!is.na(level) & level %in% LEVELS, level, "not analysed")),
    levels = LEVELS)
  nodes$label <- ifelse(is.na(nodes$name), nodes$id, nodes$name)

  g <- graph_from_data_frame(edges, directed = TRUE, vertices =
                               nodes[, c("id", "label", "level")])
  V(g)$degree <- igraph::degree(g)

  # The layout is randomised, so the seed is fixed to keep the figure stable
  # between runs.
  set.seed(SEED)
  layout <- layout_of(g)
  layout <- spread_layout(layout, SPREAD)
  layout <- pull_in_layout(layout, PULL.IN)

  # The layout is fitted to span two columns of the paper.
  layout <- scale(layout, center = TRUE, scale = FALSE)
  layout <- layout %*% svd(layout)$v
  layout <- layout / diff(range(layout[, 2]))

  # Ensure that the graph is preferably stretched sideways rather than upwards.
  natural <- diff(range(layout[, 1]))
  if (ASPECT > natural) {
    layout[, 1] <- layout[, 1] * ASPECT / natural
  }

  # Reduce node overlapping.
  layout <- separate_nodes(layout, V(g)$degree, GRAPH.SIZES, NODE.GAP)
  layout <- sweep(layout, 2, apply(layout, 2, min))
  net <- ggnetwork(g, layout = layout, scale = FALSE)
  # Ensure that the legend label order stays in ggnetwork.
  net$level <- factor(net$level, levels = LEVELS)

  # Draw packages with metrics last.
  net <- net[order(net$level), ]

  list(net = net, graph = g, nodes = nodes, release = release)
}

#' Lay out the neighbourhood of one package, keeping the coordinates of the
#' whole graph so that the result looks like a zoom into it.
#'
#' @param entry the release as build_net() returned it.
#' @param id the package in the centre.
#' @param order the number of hops around it.
#' @return the nodes and edges of the neighbourhood.
#'
zoom_net <- function(entry, id, order = 1) {
  g <- entry$graph
  centre <- which(V(g)$name == id)

  around <- igraph::ego(g, order = order, nodes = centre, mode = "all")[[1]]
  sub <- igraph::induced_subgraph(g, around)

  # Use a Kamada-Kawai layout to keep nodes centered in the panel but avoid
  # overlapping.
  set.seed(SEED)
  layout <- igraph::layout_with_kk(sub)
  net <- ggnetwork(sub, layout = layout, scale = TRUE)
  net$level <- factor(net$level, levels = LEVELS)
  net[order(net$level), ]
}

#' Get the coordinates of the neighbourhood of a package inside the layout of
#' the whole graph, which is where the zoom is taken from.
#'
#' @param entry the release as build_net() returned it.
#' @param id the package in the centre.
#' @param order the number of hops around it.
#' @param pad the margin around the neighbourhood, in layout units.
#' @return the corners of the region.
#'
zoom_region <- function(entry, id, order = 1, pad = 0.04) {
  centre <- which(V(entry$graph)$name == id)
  around <- V(entry$graph)$name[igraph::ego(entry$graph, order = order,
                                            nodes = centre, mode = "all")[[1]]]
  nodes <- entry$net[entry$net$name %in% around &
                       entry$net$x == entry$net$xend, c("x", "y")]
  list(xmin = min(nodes$x) - pad, xmax = max(nodes$x) + pad,
       ymin = min(nodes$y) - pad, ymax = max(nodes$y) + pad)
}

#' Pick the package the annotation box describes.
#'
#' @param entry the release as build_net() returned it.
#' @return the id of the package.
#'
annotated_package <- function(entry) {
  matches <- entry$nodes$id[entry$nodes$id == ANNOTATED |
                              entry$nodes$name == ANNOTATED]
  if (length(matches) == 0) {
    stop(sprintf("%s does not contain '%s'.", entry$release, ANNOTATED))
  }
  matches[1]
}

#' Build the text of the annotation box, in the layout of the tooltips of
#' the interactive graph.
#'
#' @param entry the release as build_net() returned it.
#' @param id the package to describe.
#' @return the text.
#'
annotation_text <- function(entry, id) {
  node <- entry$nodes[entry$nodes$id == id, , drop = FALSE]

  # Use short names to ensure the box stays narrow.
  short <- c(cyclomatic_complexity_per_function = "complexity/function",
             severe_osv_count = "severe vulns",
             attention_score = "attention score",
             upstream_repo = "upstream",
             downstream_repo = "downstream",
             newcomer_ratio = "newcomer ratio",
             corrective_ratio = "corrective ratio")

  lines <- vapply(ANNOTATE.METRICS, function(attribute) {
    # Get the metric value.
    value <- node[[attribute]][1]
    if (is.na(value) || value == "") {
      return(NA_character_)
    }
    # Get the metric short name.
    label <- if (attribute %in% names(short)) {
      short[[attribute]]
    } else {
      gsub("_", " ", attribute)
    }

    # A URL may be longer than the box is wide, so we cut it.
    if (grepl("_repo$", attribute)) {
      parts <- strsplit(sub("\\.git$", "", sub("^https?://", "", value)),
                        "/")[[1]]
      shown <- function(kept) {
        paste(c(kept, if (length(kept) < length(parts)) "..."), collapse = "/")
      }
      kept <- parts
      while (length(kept) > 1 && nchar(label) + nchar(shown(kept)) + 2 > 34) {
        kept <- kept[-length(kept)]
      }
      value <- shown(kept)
    }

    # The score is reported with the attention level it falls into, as the
    # graph colours the package by the level rather than by the number.
    if (attribute == "attention_score") {
      value <- sprintf("%.2f (%s)", as.numeric(value),
                       node$attention_level[1])
    }

    # Add a separator to large counts.
    number <- suppressWarnings(as.numeric(value))
    if (!is.na(number) && number >= 1000 && number == round(number)) {
      value <- formatC(number, format = "d", big.mark = ",")
    }
    sprintf("%s: %s", label, value)
  }, "")

  title <- if (!is.na(node$name[1]) && node$name[1] != "") node$name[1] else id
  paste(c(title, lines[!is.na(lines)]), collapse = "\n")
}

#' Shorten every edge so that its arrowhead stops before the package it
#' points at, by a gap that grows with the size of that package.
#'
#' @param net the nodes and edges as ggnetwork() returned them.
#' @param sizes the range the packages are drawn at, in millimetres.
#' @param gap the gap for the largest package, in units of the layout.
#' @return the edges, shortened.
#'
clear_arrowheads <- function(net, sizes, gap) {
  is_node <- net$x == net$xend & net$y == net$yend
  if (all(is_node)) {
    return(net)
  }

  # Recompute the diameter ggplot draws for every package to adjust the gap
  # between the arrowhead and the package it points at.
  span <- range(net$degree, na.rm = TRUE)
  fraction <- if (diff(span) > 0) {
    sqrt((net$degree - span[1]) / diff(span))
  } else {
    rep(1, nrow(net))
  }
  drawn <- sizes[1] + (sizes[2] - sizes[1]) * fraction

  # Lookup the size of the package node an edge points at,
  at <- function(x, y) paste(round(x, 6), round(y, 6))
  size_of <- setNames(drawn[is_node], at(net$x[is_node], net$y[is_node]))
  target <- unname(size_of[at(net$xend, net$yend)])
  target[is.na(target)] <- sizes[1]

  dx <- net$xend - net$x
  dy <- net$yend - net$y
  length <- sqrt(dx^2 + dy^2)

  # Scale the gap where the edge points at to the size of the package.
  back <- gap * target / sizes[2]

  # Limit the gap to a quarter of the edge length maximum.
  back <- pmin(back, 0.25 * length)
  shortened <- ifelse(length > 0, (length - back) / length, 0)
  keep <- !is_node & length > 0
  net$xend[keep] <- net$x[keep] + dx[keep] * shortened[keep]
  net$yend[keep] <- net$y[keep] + dy[keep] * shortened[keep]
  net
}

#' Draw a laid out graph.
#'
#' @param net the nodes and edges as ggnetwork() returned them.
#' @param zoom whether this is the enlarged neighbourhood.
#' @param highlight the package to ring, if any.
#' @return the plot.
#'
network_plot <- function(net, zoom = FALSE, highlight = NULL) {
  sizes <- if (zoom) ZOOM.SIZES else GRAPH.SIZES
  net <- clear_arrowheads(net, sizes, if (zoom) ARROW.GAP * 1.5
                          else ARROW.GAP)

  p <- ggplot(net, aes(x = x, y = y, xend = xend, yend = yend)) +
    geom_edges(colour = COLOURS.LIST.DARK[2], linetype = "solid",
               linewidth = LINE.SIZE.THIN * 0.55, alpha = 0.7,
               arrow = arrow(length = unit(if (zoom) 3.2 else 1.6, "pt"),
                             type = "closed")) +
    geom_nodes(aes(fill = level, size = degree), shape = 21,
               colour = "black", stroke = 0.25) +
    scale_fill_manual(values = LEVEL.COLOURS, drop = FALSE) +
    scale_size_continuous(range = sizes, guide = "none") +
    # Add padding to keep the package names inside.
    scale_x_continuous(expand = expansion(mult = if (zoom) ZOOM.EXPAND.X
                                          else GRAPH.EXPAND)) +
    scale_y_continuous(expand = expansion(mult = if (zoom) ZOOM.EXPAND.Y
                                          else GRAPH.EXPAND)) +
    theme_paper_base() +
    theme(axis.title.x = element_blank(),
          axis.title.y = element_blank(),
          axis.text = element_blank(),
          axis.ticks = element_blank(),
          # Blanking the ticks hides them but still reserves their length,
          # which offsets the panel from the area it is drawn into.
          axis.ticks.length = unit(0, "pt"),
          panel.grid = element_blank(),
          panel.border = element_blank())

  if (!zoom) {
    p <- p + coord_fixed(ratio = 1, clip = "off")
  }

  if (zoom) {
    # In the zoom every package is named, which is what the box in the
    # interactive graph shows.
    named <- net[net$x == net$xend & net$y == net$yend, ]

    # Add node names.
    p <- p + ggrepel::geom_text_repel(
      data = named, aes(x = x, y = y, label = label),
      size = TABLE.FONT.SIZE, colour = "black",
      point.size = ZOOM.SIZES[2], point.padding = unit(2, "pt"),
      box.padding = unit(2, "pt"),
      force = 3, force_pull = 0.3, max.iter = 20000,
      segment.size = 0.2, min.segment.length = 0.1, max.overlaps = Inf,
      seed = SEED, inherit.aes = FALSE)
  }

  if (!is.null(highlight)) {
    # A circle marks the package the figure focuses on.
    node <- net[net$name == highlight & net$x == net$xend, ][1, ]
    p <- p + annotate("point", x = node$x, y = node$y, shape = 21, size = 3.4,
                      stroke = 0.5, colour = COLOURS.LIST.DARK[5], fill = NA)
  }

  p
}

#' Draw a step title as in the method figure, with the number in a circle,
#' followed by the title.
#'
#' @param number the number of the step.
#' @param text the title.
#' @param x the left edge on the canvas.
#' @param y the bottom edge on the canvas.
#' @return the layers to add to the canvas.
#'
step_title <- function(number, text, x, y) {
  diameter <- 0.11
  width <- diameter / FIGURE.WIDTH
  height <- diameter / FIGURE.HEIGHT
  list(
    draw_grob(circleGrob(r = 0.5, gp = gpar(col = "black", fill = NA,
                                            lwd = 0.6)),
              x = x, y = y, width = width, height = height),
    draw_label(number, x = x + width / 2, y = y + height / 2,
               size = TINY.SIZE),
    draw_label(text, x = x + width + 0.004, y = y + height / 2, hjust = 0,
               size = SMALL.SIZE)
  )
}

#' Draw a mouse pointer whose tip points at a position on the canvas.
#'
#' @param x the horizontal position of the tip.
#' @param y the vertical position of the tip.
#' @return the layer to add to the canvas.
#'
mouse_pointer <- function(x, y) {
  size <- 0.11
  outline <- polygonGrob(x = c(0, 0, 0.36, 0.6, 0.8, 0.56, 1),
                         y = c(1, 0.22, 0.42, 0.04, 0.11, 0.48, 0.48),
                         gp = gpar(col = "black", fill = "white", lwd = 0.6))
  draw_grob(outline, x = x, y = y - size / FIGURE.HEIGHT,
            width = 0.75 * size / FIGURE.WIDTH, height = size / FIGURE.HEIGHT)
}

#' Draw a browser window around the canvas, with a frame and a top bar with
#' buttons and an address field.
#'
#' @param bar_height the height of the top bar on the canvas.
#' @param bottom the bottom edge of the window on the canvas.
#' @return the layers to add to the canvas.
#'
browser_window <- function(bar_height, bottom) {
  inset <- 0.002
  bar_y <- 1 - inset - bar_height
  dot <- 0.055
  dots <- lapply(0:2, function(i) {
    draw_grob(circleGrob(r = 0.5, gp = gpar(col = "grey55", fill = "grey85",
                                            lwd = 0.5)),
              x = inset + 0.008 + i * 0.011,
              y = bar_y + bar_height / 2 - dot / FIGURE.HEIGHT / 2,
              width = dot / FIGURE.WIDTH, height = dot / FIGURE.HEIGHT)
  })
  field_x <- inset + 0.05
  field_height <- 0.62 * bar_height
  c(list(
    draw_grob(roundrectGrob(r = unit(CORNER.RADIUS, "pt"),
                            gp = gpar(col = "grey55", fill = NA, lwd = 0.6)),
              x = inset, y = bottom, width = 1 - 2 * inset,
              height = 1 - inset - bottom),
    draw_line(x = c(inset, 1 - inset), y = c(bar_y, bar_y), colour = "grey55",
              linewidth = 0.25),
    draw_grob(roundrectGrob(r = unit(2, "pt"),
                            gp = gpar(col = "grey70", fill = "white",
                                      lwd = 0.5)),
              x = field_x, y = bar_y + (bar_height - field_height) / 2,
              width = 0.5, height = field_height),
    draw_label(paste0("https://", WEBSITE, "/graphs/trixie-score.html"),
               x = field_x + 0.008, y = bar_y + bar_height / 2, hjust = 0,
               size = TINY.SIZE, colour = "grey30")
  ), dots)
}

#' Draw an arrow from the end of a step title to the circle of the next step.
#'
#' @param text the title of the step.
#' @param x the left edge of the step on the canvas.
#' @param next_x the left edge of the next step on the canvas.
#' @param y the bottom edge of the steps on the canvas.
#' @return the layer to add to the canvas.
#'
step_arrow <- function(text, x, next_x, y) {
  # Measure the title on a device which writes no file. Its Helvetica is
  # wider than the Times of the paper.
  grDevices::pdf(NULL)
  on.exit(grDevices::dev.off())
  text_width <- 0.85 * convertWidth(grobWidth(textGrob(text, gp = gpar(
    fontsize = SMALL.SIZE))), "inches", valueOnly = TRUE)
  start <- x + (0.11 + text_width) / FIGURE.WIDTH + 0.014
  draw_line(x = c(start, next_x - 0.009),
            y = rep(y + 0.11 / FIGURE.HEIGHT / 2, 2), colour = "black",
            linewidth = LINE.SIZE.THIN,
            arrow = arrow(length = unit(2.5, "pt"), type = "closed"))
}

#' Get the height of the metrics box, which fits its lines.
#'
#' @param entry the release as build_net() returned it.
#' @param id the package the box describes.
#' @return the height in inches.
#'
box_height <- function(entry, id) {
  lines <- length(strsplit(annotation_text(entry, id), "\n")[[1]])
  (lines * TINY.SIZE * BOX.LINE.HEIGHT + BOX.PADDING) / 72.27
}

#' Get the height of the figure, so that the browser window closes closely
#' around the release graph and the metrics box, whichever is taller.
#'
#' @param entry the release as build_net() returned it.
#' @param id the package the metrics box describes.
#' @return the height in inches.
#'
figure_height <- function(entry, id) {
  packages <- GRAPH.PANEL * FIGURE.WIDTH / max(entry$net$x) /
    (1 + 2 * GRAPH.EXPAND)
  max(packages, box_height(entry, id)) + 2 * GAPS[["frame"]] +
    sum(GAPS[c("bottom", "steps", "between", "bar", "top")])
}

#' Draw the composed figure: the graph of the release, a rounded frame around
#' the neighbourhood the zoom is taken from, and the box of metrics beside
#' that.
#'
#' @param entry the release as build_net() returned it.
#' @param id the package in the centre of the zoom.
#' @return the composed figure.
#'
example_figure <- function(entry, id) {
  bare <- theme(plot.margin = margin(0, 0, 0, 0),
                plot.title = element_blank(),
                legend.position = "none")

  # Left: the graph of the whole release.
  region <- zoom_region(entry, id, REGION.ORDER)
  overview <- network_plot(entry$net) + bare +
    annotation_custom(roundrectGrob(r = unit(CORNER.RADIUS, "pt"),
                                    gp = gpar(col = "black",
                                              fill = NA, lwd = 0.8)),
                      xmin = region$xmin, xmax = region$xmax,
                      ymin = region$ymin, ymax = region$ymax)

  # Middle: the neighbourhood of the package the example walks through.
  detail <- network_plot(zoom_net(entry, id, ZOOM.ORDER), zoom = TRUE,
                         highlight = id) + bare

  # Arrange the canvas from the bottom: the step titles below the browser
  # window, the band of panels inside its frame, and its top bar.
  inch <- function(v) v / FIGURE.HEIGHT
  bar_height <- inch(GAPS[["bar"]])
  step_y <- inch(GAPS[["bottom"]])
  window_y <- step_y + inch(GAPS[["steps"]] + GAPS[["between"]])
  band <- list(y = window_y + inch(GAPS[["frame"]]))
  band_top <- 1 - inch(GAPS[["top"]]) - bar_height - inch(GAPS[["frame"]])
  band$height <- band_top - band$y
  centre <- band$y + band$height / 2
  aspect <- max(entry$net$x)
  padded <- 1 + 2 * GRAPH.EXPAND

  # Split the canvas into three panels, with a gap between them.
  gap <- 0.014
  left <- list(x = 0.004, width = GRAPH.PANEL)
  middle <- list(width = 0.190)
  right <- list(width = 0.195)
  middle$x <- left$x + left$width + gap
  right$x <- middle$x + middle$width + gap

  # Centre the panels in the window. The release graph is padded, so its
  # leftmost package, not its panel, marks the left edge of the content.
  smallest <- GRAPH.SIZES[1] / 2 / 25.4 / FIGURE.WIDTH
  content_left <- left$x + left$width * GRAPH.EXPAND / padded - smallest
  shift <- (content_left + right$x + right$width) / 2 - 0.5
  left$x <- left$x - shift
  middle$x <- middle$x - shift
  right$x <- right$x - shift

  # Derive the height of the release graph from its width, and centre all
  # panels in the band. The padding of the graph may reach beyond the band,
  # as long as the packages themselves stay inside it. The neighbourhood
  # panel is a bit smaller to show that it is a zoom, and the metrics box
  # fits its lines.
  left$height <- left$width / aspect * FIGURE.WIDTH / FIGURE.HEIGHT
  left$y <- centre - left$height / 2
  middle$height <- left$height * 0.80
  middle$y <- centre - middle$height / 2
  right$height <- inch(box_height(entry, id))
  right$y <- centre - right$height / 2

  # Account for the corner radius of the rounded panels when drawing the lines
  # which tie the panels together.
  corner_r <- CORNER.RADIUS / (FIGURE.HEIGHT * 72.27)
  # Map a point in the release graph to the canvas as starting point of
  # the lines to the neighbourhood panel. Scale layout coordinates to the
  # panel.
  place_x <- function(v) {
    left$x + left$width * (v / aspect + GRAPH.EXPAND) / padded
  }
  place_y <- function(v) {
    left$y + left$height * (v + GRAPH.EXPAND) / padded
  }

  titles <- c(paste(entry$release, "release graph"),
              "Zoom into neighbourhood", "Click for package details")

  # Draw the release graph, the step titles and the arrows between them.
  canvas <- ggdraw() +
    draw_plot(overview, x = left$x, y = left$y, width = left$width,
              height = left$height) +
    step_title("1", titles[1], 0.004, step_y) +
    step_arrow(titles[1], 0.004, middle$x, step_y) +
    step_arrow(titles[2], middle$x, right$x, step_y)

  # Draw the dashed line to the neighbourhood panel.
  for (corner in c(1, 0)) {
    canvas <- canvas +
      draw_line(x = c(place_x(region$xmax), middle$x),
                y = c(place_y(if (corner == 1) region$ymax else region$ymin),
                      middle$y + corner_r +
                        (middle$height - 2 * corner_r) * corner),
                colour = "black", linewidth = LINE.SIZE.THIN,
                linetype = "dashed")
  }

  # Find the example package in the neighbourhood panel and map its
  # coordinates to the canvas.
  node <- detail$data[detail$data$name == id &
                        detail$data$x == detail$data$xend, ][1, ]
  node_x <- middle$x + middle$width *
    (node$x + ZOOM.EXPAND.X[1]) / (1 + sum(ZOOM.EXPAND.X))
  node_y <- middle$y + middle$height *
    (node$y + ZOOM.EXPAND.Y[1]) / (1 + sum(ZOOM.EXPAND.Y))

  # Draw the neighbourhood panel.
  canvas <- canvas +
    draw_plot(detail, x = middle$x, y = middle$y, width = middle$width,
              height = middle$height)

  # Draw the lines from the package in the neighbourhood panel to the
  # metrics box.
  for (corner in c(1, 0)) {
    canvas <- canvas +
      draw_line(x = c(node_x, right$x),
                y = c(node_y, right$y + corner_r +
                        (right$height - 2 * corner_r) * corner),
                colour = "black", linewidth = LINE.SIZE.THIN,
                linetype = "dashed")
  }

  # Draw the frames and titles of the neighbourhood panel and the metrics box.
  canvas +
    # Neighbourhood frame and title.
    draw_grob(roundrectGrob(r = unit(CORNER.RADIUS, "pt"),
                            gp = gpar(col = "black", fill = NA,
                                      lwd = 0.8)),
              x = middle$x, y = middle$y, width = middle$width,
              height = middle$height) +
    step_title("2", titles[2], middle$x, step_y) +
    # Metrics box frame, text and title.
    draw_grob(roundrectGrob(r = unit(CORNER.RADIUS, "pt"),
                            gp = gpar(col = "black", fill = "white",
                                      lwd = 0.8)),
              x = right$x, y = right$y, width = right$width,
              height = right$height) +
    draw_label(annotation_text(entry, id), x = right$x + 0.012,
               y = right$y + right$height / 2, hjust = 0, vjust = 0.5,
               size = TINY.SIZE, lineheight = BOX.LINE.HEIGHT) +
    step_title("3", titles[3], right$x, step_y) +
    mouse_pointer(node_x + 0.003, node_y + 0.006) +
    browser_window(bar_height, window_y)
}

# Create the graph layout.
entry <- build_net(GRAPH, RELEASE)
# Locate the package the annotation box describes.
id <- annotated_package(entry)
# Fit the height of the figure to its content, and save it.
FIGURE.HEIGHT <- figure_height(entry, id)
save_plot(example_figure(entry, id), "network_example",
          width = FIGURE.WIDTH, height = FIGURE.HEIGHT)
# Make the website clickable in the LaTeX version of the figure.
tex_file <- file.path(OUTDIR_TIKZ, "network_example.tex")
# A link in scaled text is only partly clickable, so the label is set in the
# font size it is scaled to instead.
url <- paste0("https://", WEBSITE, "/graphs/trixie-score.html")
tex <- readLines(tex_file)
link <- grep(url, tex, fixed = TRUE)
scale <- as.numeric(sub(".*scale= *([0-9.]+)\\].*", "\\1", tex[link]))
tex[link] <- sub(", scale= *[0-9.]+\\]", "]", tex[link])
tex[link] <- sub(") {", sprintf(") {\\fontsize{%.2f}{%.2f}\\selectfont ",
                               10 * scale, 12 * scale), tex[link], fixed = TRUE)
tex[link] <- sub(url, sprintf("\\href{%s}{%s}", url, url), tex[link],
                 fixed = TRUE)
writeLines(tex, tex_file)
