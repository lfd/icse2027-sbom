import logging
import math

from networkx import DiGraph,read_graphml, set_node_attributes, write_graphml, descendants
from dataclasses import dataclass, field
from pyvis.network import Network

from sbom_analysis.analyse.metrics_summary import MetricsSummary

logger = logging.getLogger(__name__)


@dataclass
class Graph:
    """
    Calculates metrics based on the extracted data.
    """

    G: DiGraph = field(default_factory=DiGraph)

    @classmethod
    def from_graphml(cls, graph_file: str):
        """
        Load dependency graph from graphml file.

        Args;
            graph_file: Path to the input GraphML file.

        Returns:
            An instance of the Graph with the loaded graph.
        """
        G = read_graphml(graph_file)
        return cls(G=G)

    def annotate(self, metrics: MetricsSummary, selected_metrics: list[str]):
        """
        Store calculated metrics for relevant packages in the dependency graph.

        Args:
            metrics: Calculated metrics to annotate the graph with.
            selected_metrics: Selected metrics that were calculated.
        """
        def get_meta(m):
            # Handle metrics that were not calculated (None) and missing values
            # in the metrics table (NaN).
            if m is None or (isinstance(m, float) and math.isnan(m)):
                return "N/A"
            return str(m)

        # Only show metrics for the latest time window.
        latest_window = max(k[1] for k in metrics.package_metrics.keys())
        latest_metrics = {
            k: v for k, v in metrics.package_metrics.items()
            if k[1] == latest_window
        }

        meta = dict()
        values = dict()

        for package_key, package_metrics in latest_metrics.items():
            package_id = package_key[0].removeprefix("SPDXRef-")

            # Format package meta information as text.
            meta[package_id] = {
                "downstream_repo": get_meta(package_metrics.downstream_url),
                "upstream_repo": get_meta(package_metrics.upstream_url),
                "downstream_checkout": get_meta(
                    package_metrics.downstream_checkout
                ),
                "downstream_path": get_meta(
                    package_metrics.downstream_path
                ),
                "upstream_checkout": get_meta(
                    package_metrics.upstream_checkout
                ),
                "downstream_primary_lang": get_meta(
                    package_metrics.downstream_primary_lang
                ),
                "upstream_primary_lang": get_meta(
                    package_metrics.upstream_primary_lang
                )
            }

            # Collect only selected metrics that were actually calculated.
            # Metrics missing for a package are not displayed.
            calculated = dict()
            for m in selected_metrics:
                if not hasattr(package_metrics, m):
                    continue
                val = getattr(package_metrics, m)
                if val is None:
                    continue
                val = float(val)
                if math.isnan(val) or math.isinf(val):
                    continue
                calculated[m] = val
            values[package_id] = calculated

        # Ensure that types are only declared once. This avoids compatibility
        # issues with oder GraphML readers that do not support multiple types,
        # as networkx writes them.
        metrics_int = {
            m for m in selected_metrics
            if any(m in v for v in values.values())
            and all(v[m].is_integer() for v in values.values() if m in v)
        }

        for package_id, calculated in values.items():
            attributes = dict(meta[package_id])
            for m, val in calculated.items():
                attributes[m] = int(val) if m in metrics_int else round(val, 4)
            set_node_attributes(self.G, {
                package_id: attributes
            })

    def annotate_scores(self, scores: dict, levels: dict, severe: dict):
        """
        Store the attention score of every package in the dependency graph.

        Args:
            scores: The score per package id.
            levels: The level per package id.
            severe: Whether a package is severely vulnerable per package id.
        """
        for package_id, value in scores.items():
            set_node_attributes(self.G, {
                package_id: {
                    "attention_score": round(float(value), 4),
                    "attention_level": str(levels[package_id]),
                    "severe": int(severe[package_id])
                }
            })
        logger.debug("Annotated %d packages with the attention score",
                    len(scores))

    def to_graphml(self, graph_file: str):
        """
        Export graph to GraphML.

        Args:
            graph_file: Path to the output GraphML file.
        """
        write_graphml(self.G, graph_file)

    def oriented_graph(self) -> DiGraph:
        """
        Returns the graph with one direction per relation.

        SPDX defines relations "generates" and its inverse "generated_from",
        which can point opposite ways for the same link. The inverse relation
        is therefore converted to ensure that reachability is calculated
        consistently everywhere.

        The stored graph, however, keeps the original SBOM directions.

        Returns:
            The graph with every "generated_from" reversed into a "generates".
        """
        oriented = DiGraph()
        oriented.add_nodes_from(self.G.nodes(data=True))
        reversed_edges = 0
        for u, v, data in self.G.edges(data=True):
            if data.get("reltype") == "generated_from":
                oriented.add_edge(v, u, **{**data, "reltype": "generates"})
                reversed_edges += 1
            else:
                oriented.add_edge(u, v, **data)

        if reversed_edges:
            logger.debug(
                "Reversed %d 'generated_from' relation(s)", reversed_edges
            )
        return oriented

    def to_pyvis(self):
        """
        Build a pyvis network from the networkx graph with
        appropriate labels, sizes, colors, and tooltips. Highlight critical
        nodes with potential maintenance issues.
        """
        net = Network(height="800px", width="800px", notebook=False,
                      directed=True)

        # Packages which could not be analysed are displayed in default colour.
        default_color = "#FFFFFF"
        border_color = "#AAAAAA"
        highlight_color = "#808080"
        # Packages with confirmed severe vulnerabilities.
        critical_color = "#BB615A"
        # Packages with a high attention level.
        high_color = "#C88B0C"
        # Packages which should receive elevated attention.
        warning_color = "#EAD3AA"
        # Packages which could be analysed but do not appear suspicious.
        ok_color = "#F8ECD3"

        critical_nodes = list()
        warning_nodes = list()
        degrees = dict(self.G.degree())
        # What a package reaches is counted on the graph with one direction
        # per relation, see oriented_graph().
        oriented = self.oriented_graph()

        for node, data in self.G.nodes(data=True):
            # Add package meta information.
            version = data.get("version", "N/A")
            down_repo = data.get("downstream_repo", "N/A")
            down_checkout = data.get("downstream_checkout", "N/A")
            down_path = data.get("downstream_path", "")
            down_primary_lang = data.get("downstream_primary_lang", "N/A")
            up_repo = data.get("upstream_repo", "N/A")
            up_checkout = data.get("upstream_checkout", "N/A")
            up_primary_lang = data.get("upstream_primary_lang", "N/A")
            project_age = data.get("project_age", "N/A")

            # Format project age in years and months.
            if isinstance(project_age, int):
                years = project_age // 12
                months = project_age % 12
                project_age = f"{years} years {months} months"

            # Add structural metrics which can be calculated for any node.
            node_deg = degrees[node]
            node_desc = len(descendants(oriented, node))

            # Show the attention score first, if calculated.
            attention = data.get("attention_score", None)
            level = data.get("attention_level", "")
            text = f"attention_score: {attention} ({level})<br>" \
                if attention is not None else "attention_score: N/A<br>"

            # OSV records Debian vulnerabilities for source packages only,
            # while binary packages yield no vulnerabilities, although they
            # are built from the same source package. Therefore, we assign
            # vulnerabilities reported for the source package to the binary
            # packages built from it as well.
            if data.get("severe", 0):
                text += "severe vulnerabilities: yes (in source package)<br>"

            text += f"version: {version}<br>" + \
                   f"downstream_repo: {down_repo}<br>" + \
                   f"downstream_checkout: {down_checkout}<br>"

            # Include downstream path for packages in mono repositories, but
            # not for others.
            if down_path not in ("", "N/A"):
                text += f"downstream_path: {down_path}<br>"

            # Include the primary language only if it could be determined.
            if down_primary_lang != "N/A":
                text += f"downstream_primary_lang: {down_primary_lang}<br>"

            text += f"upstream_repo: {up_repo}<br>" + \
                   f"upstream_checkout: {up_checkout}<br>"

            if up_primary_lang != "N/A":
                text += f"upstream_primary_lang: {up_primary_lang}<br>"

            text += f"project_age: {project_age}<br>"

            # Adjust node appearance based on the calculated metrics.
            size = min(math.log(degrees[node] + 1) * 8 + 10, 64)
            analysed = False

            # A package which could not be scored stays white.
            color = ok_color if attention is not None else default_color

            for att in data:
                if att in [
                    "name",
                    "version",
                    "purl",
                    "purpose",
                    "downstream_repo",
                    "downstream_checkout",
                    "downstream_path",
                    "downstream_primary_lang",
                    "upstream_repo",
                    "upstream_checkout",
                    "upstream_primary_lang",
                    "project_age",
                    "severe",
                    "attention_score"
                ]:
                    continue
                elif data.get(att, "") not in ("", None):
                    # Get metrics of nodes if their repository could be
                    # analysed.
                    metric_val = data.get(att, "")

                    # Skip descriptive package meta information that is not
                    # numeric.
                    try:
                        value = float(metric_val)
                    except (TypeError, ValueError):
                        continue

                    # Hide metrics that could not be calculated. This
                    # prevents displaying a large list of nan values, for
                    # instance if static analysis metrics could not be
                    # calculated for a certain repository if it does not
                    # contain and relevant code.
                    if math.isnan(value):
                        continue

                    text += f"{att}: {metric_val}<br>"
                    analysed = True

                    # A confirmed severe vulnerability outranks every score.
                    confirmed = (att in ("critical_osv_count",
                                         "high_osv_count") and value > 0)
                    if confirmed and node not in critical_nodes:
                        critical_nodes.append(node)

            # Add severe vulnerability status.
            if data.get("severe", 0) and node not in critical_nodes:
                critical_nodes.append(node)

            if node in critical_nodes:
                color = critical_color
            elif level == "high":
                color = high_color
                if node not in warning_nodes:
                    warning_nodes.append(node)
            elif level == "elevated":
                color = warning_color
                if node not in warning_nodes:
                    warning_nodes.append(node)

            if analysed:
                color = {"background": color,
                         "border": border_color,
                         "highlight": {"background": color,
                                       "border": highlight_color}}
            else:
                color = {"background": default_color,
                         "border":border_color,
                         "highlight": {"background": default_color,
                                       "border": highlight_color}}

            text += f"first_degree_dependencies: {node_deg}<br>" + \
                    f"transitive_dependencies: {node_desc}<br>"

            net.add_node(node, label=node, size=size, color=color,
                         tooltip=text)

        # Add edges with color based on whether they are transitively dependent
        # on a critical or warning node. Use the oriented graph for
        # consistency.
        for u, v in oriented.edges():
            if u in critical_nodes or v in critical_nodes:
                color = critical_color
                width = 3
            elif u in warning_nodes or v in warning_nodes:
                color = warning_color
                width = 2
            else:
                color = border_color
                width = 1
            net.add_edge(u, v, color=color, width=width)
        return net

    def to_html(self, graph_file: str):
        """
        Export graph to interactive HTML.

        Args:
            graph_file: Path to the output HTML file.
        """
        net = self.to_pyvis()

        # Store the graph to an HTML file.
        net.write_html(graph_file, local=False)

        # Post-process the HTML file to add a click event for displaying node
        # details, i.e. metrics calculated for the package.
        with open(graph_file, "r") as f:
            html = f.read()

        click_js = """
        <script type="text/javascript">
            var infoBox = document.createElement('div');
            infoBox.id = 'infoBox';
            infoBox.innerHTML = 'Click a node for details.';
            infoBox.style.position = 'absolute';
            infoBox.style.top = '20px';
            infoBox.style.left = '10px';
            infoBox.style.backgroundColor = 'rgba(255,255,255,0.9)';
            infoBox.style.padding = '10px';
            infoBox.style.borderRadius = '5px';
            infoBox.style.boxShadow = '0px 0px 5px gray';
            infoBox.style.maxWidth = '460px';
            infoBox.style.fontFamily = 'sans-serif';
            infoBox.style.fontSize = '12px';
            infoBox.style.pointerEvents = 'none';
            document.body.appendChild(infoBox);
    
            network.on("click", function(params) {
                if(params.nodes.length > 0) {
                    var node = nodes.get(params.nodes[0]);
                    infoBox.innerHTML = "<b>" + node.label +
                    "</b><br>" + (node.tooltip || "");
                } else {
                    infoBox.innerHTML = "Click a node for details.";
                }
            });
        </script>
        """
        html = html.replace("</body>", click_js + "\n</body>")

        with open(graph_file, "w") as f:
            f.write(html)