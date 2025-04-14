Project Title: Interactive OSM Data Extractor and Viewer

Objective: Develop a web-based interactive mapping tool that allows users to select an area of interest using a draggable bounding box over a live, open-source map. Upon selection, the tool should:

Extract the perimeter coordinates (and optionally the polygon shape) of the selected region.

Query the OpenStreetMap (OSM) dataset via the Overpass API to fetch up-to-date, vector-based geographic data—including buildings, roads, trees, rivers, and other points of interest—for that area.

Render the retrieved spatial data on a high-resolution, fully zoomable map interface (capable of meter-level detail) without relying on proprietary services.

Technical Requirements:

Frontend Mapping Library: Use an open-source, Mapbox GL JS–compatible library like MapLibre GL JS to display vector tiles derived from OSM data without requiring an API token.

Data Extraction: Implement a draggable bounding box selection tool on the map. Once the user drags and releases the bounding box, extract the precise perimeter coordinates and use them to define the spatial query.

Data Query and Conversion:

Use the Overpass API to query detailed OSM data within the defined bounding box.

Target features should include, but are not limited to, building footprints, highway networks, trees (nodes tagged with natural=tree), and water features (such as rivers tagged with waterway=river).

Convert the Overpass JSON response into GeoJSON format using a library like osmtogeojson for easy integration with the map layers.

Map Display and Interactivity:

Render the fetched GeoJSON data as separate, custom-styled layers (e.g., fill layers for buildings, line layers for roads and rivers, and circle layers for trees) on the MapLibre map.

Provide intuitive navigation controls (zoom, pan, rotation) and possibly additional functionalities like full-screen mode.

Optionally log or display the current bounding coordinates and zoom level after each selection for reference or further processing.

Expected Outcome: A fully interactive, web-based tool that lets users dynamically select any region (for example, Manhattan) and immediately view a detailed, vector-based map of that area with real-time OSM data, showcasing the latest buildings, roads, vegetation, and water bodies.
