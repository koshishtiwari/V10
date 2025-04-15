import React, { useState, useEffect, useRef } from 'react';
import { MapContainer, TileLayer, useMap, Rectangle, FeatureGroup } from 'react-leaflet';
import { EditControl } from "react-leaflet-draw";
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import 'leaflet-draw/dist/leaflet.draw.css';

// Fix Leaflet icon issues
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png'
});

// Map styles for different OSM features
const mapStyles = {
  buildings: { color: '#8B4513', weight: 1, fillColor: '#D2B48C', fillOpacity: 0.7 },
  roads: { color: '#696969', weight: 3 },
  water: { color: '#4682B4', weight: 1, fillColor: '#B0E0E6', fillOpacity: 0.7 },
  vegetation: { color: '#228B22', weight: 1, fillColor: '#90EE90', fillOpacity: 0.7 }
};

const MapSelector = () => {
  const [mainCenter, setMainCenter] = useState([40.7831, -73.9712]); // Default to Manhattan
  const [zoomLevel, setZoomLevel] = useState(12);
  const [selectedBounds, setSelectedBounds] = useState(null);
  const [showExtractedMap, setShowExtractedMap] = useState(false);
  const [loading, setLoading] = useState(false);
  const [featuresData, setFeaturesData] = useState({
    buildings: [],
    roads: [],
    water: [],
    vegetation: []
  });
  const featureGroupRef = useRef(null);

  // Component to extract data from Overpass API
  const DataExtractor = () => {
    const map = useMap();
    
    useEffect(() => {
      if (!selectedBounds || !showExtractedMap) return;
      
      setLoading(true);
      
      const bounds = selectedBounds;
      const south = bounds.getSouth();
      const west = bounds.getWest();
      const north = bounds.getNorth();
      const east = bounds.getEast();
      
      // Create Overpass API query for different feature types
      const buildingsQuery = `
        [out:json];
        (
          way[building]
            (${south},${west},${north},${east});
        );
        out body geom;
      `;
      
      const roadsQuery = `
        [out:json];
        (
          way[highway]
            (${south},${west},${north},${east});
        );
        out body geom;
      `;
      
      const waterQuery = `
        [out:json];
        (
          way[natural=water]
            (${south},${west},${north},${east});
          relation[natural=water]
            (${south},${west},${north},${east});
        );
        out body geom;
      `;
      
      const vegetationQuery = `
        [out:json];
        (
          way[landuse=forest]
            (${south},${west},${north},${east});
          way[natural=wood]
            (${south},${west},${north},${east});
          way[landuse=grass]
            (${south},${west},${north},${east});
          way[leisure=park]
            (${south},${west},${north},${east});
        );
        out body geom;
      `;
      
      // Function to query Overpass API
      const fetchOsmData = async (query, featureType) => {
        try {
          const encodedQuery = encodeURIComponent(query);
          const response = await fetch(`https://overpass-api.de/api/interpreter?data=${encodedQuery}`);
          const data = await response.json();
          
          // Convert to GeoJSON
          const features = data.elements.map(element => {
            if (element.type === 'way') {
              const coordinates = element.geometry.map(node => [node.lat, node.lon]);
              return L.polygon(coordinates, mapStyles[featureType]);
            }
            return null;
          }).filter(Boolean);
          
          return features;
        } catch (error) {
          console.error(`Error fetching ${featureType}:`, error);
          return [];
        }
      };
      
      // Fetch all data types
      Promise.all([
        fetchOsmData(buildingsQuery, 'buildings'),
        fetchOsmData(roadsQuery, 'roads'),
        fetchOsmData(waterQuery, 'water'),
        fetchOsmData(vegetationQuery, 'vegetation')
      ]).then(([buildings, roads, water, vegetation]) => {
        setFeaturesData({
          buildings,
          roads,
          water,
          vegetation
        });
        setLoading(false);
      }).catch(error => {
        console.error("Error loading OSM data:", error);
        setLoading(false);
      });
      
    }, [showExtractedMap, selectedBounds]);
    
    return null;
  };

  // Handle draw events
  const onCreated = (e) => {
    const { layerType, layer } = e;
    
    if (layerType === 'rectangle') {
      setSelectedBounds(layer.getBounds());
    }
  };
  
  const onDeleted = () => {
    setSelectedBounds(null);
    setShowExtractedMap(false);
  };
  
  const handleExtractMap = () => {
    if (selectedBounds) {
      setShowExtractedMap(true);
    } else {
      alert("Please select a region first");
    }
  };
  
  const resetView = () => {
    setShowExtractedMap(false);
    setSelectedBounds(null);
    
    // Clear the drawn items
    if (featureGroupRef.current) {
      featureGroupRef.current.clearLayers();
    }
  };
  
  return (
    <div className="flex flex-col h-screen">
      <div className="bg-blue-600 p-4 text-white">
        <h1 className="text-xl font-bold">Interactive OpenStreetMap Region Selector</h1>
      </div>
      
      <div className="flex flex-col md:flex-row flex-1">
        <div className="md:w-1/2 p-4 flex flex-col">
          <h2 className="text-lg font-semibold mb-2">
            {showExtractedMap ? "Selected Region" : "Select a Region"}
          </h2>
          
          <div className="flex-1 border border-gray-300 rounded">
            <MapContainer 
              center={mainCenter} 
              zoom={zoomLevel} 
              style={{ height: "100%", width: "100%" }}
            >
              <TileLayer
                url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
              />
              
              {!showExtractedMap && (
                <FeatureGroup ref={featureGroupRef}>
                  <EditControl
                    position="topright"
                    onCreated={onCreated}
                    onDeleted={onDeleted}
                    draw={{
                      circle: false,
                      circlemarker: false,
                      marker: false,
                      polyline: false,
                      polygon: false,
                      rectangle: true
                    }}
                  />
                </FeatureGroup>
              )}
              
              {showExtractedMap && selectedBounds && (
                <Rectangle bounds={selectedBounds} pathOptions={{ color: '#ff7800', weight: 1 }} />
              )}
            </MapContainer>
          </div>
          
          <div className="mt-4 flex space-x-2">
            {!showExtractedMap && (
              <button 
                onClick={handleExtractMap}
                disabled={!selectedBounds}
                className={`px-4 py-2 rounded ${selectedBounds ? 'bg-green-600 text-white' : 'bg-gray-300 text-gray-600'}`}
              >
                Extract Selected Region
              </button>
            )}
            
            {showExtractedMap && (
              <button 
                onClick={resetView}
                className="bg-red-600 text-white px-4 py-2 rounded"
              >
                Reset Selection
              </button>
            )}
          </div>
        </div>
        
        <div className="md:w-1/2 p-4 flex flex-col">
          <h2 className="text-lg font-semibold mb-2">
            {showExtractedMap ? "Detailed Vector Map" : "Select a region on the left to view detailed data"}
          </h2>
          
          <div className="flex-1 border border-gray-300 rounded">
            {showExtractedMap && selectedBounds ? (
              <MapContainer 
                bounds={selectedBounds}
                style={{ height: "100%", width: "100%" }}
              >
                <TileLayer
                  url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                  attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                />
                
                <DataExtractor />
                
                {loading ? (
                  <div className="absolute inset-0 flex items-center justify-center bg-white bg-opacity-70 z-50">
                    <div className="text-lg">Loading OSM data...</div>
                  </div>
                ) : (
                  <>
                    {featuresData.buildings.map((building, idx) => (
                      <React.Fragment key={`building-${idx}`}>
                        {building}
                      </React.Fragment>
                    ))}
                    
                    {featuresData.roads.map((road, idx) => (
                      <React.Fragment key={`road-${idx}`}>
                        {road}
                      </React.Fragment>
                    ))}
                    
                    {featuresData.water.map((waterBody, idx) => (
                      <React.Fragment key={`water-${idx}`}>
                        {waterBody}
                      </React.Fragment>
                    ))}
                    
                    {featuresData.vegetation.map((vegetationArea, idx) => (
                      <React.Fragment key={`vegetation-${idx}`}>
                        {vegetationArea}
                      </React.Fragment>
                    ))}
                  </>
                )}
              </MapContainer>
            ) : (
              <div className="h-full flex items-center justify-center bg-gray-100 text-gray-500">
                No region selected
              </div>
            )}
          </div>
          
          {showExtractedMap && (
            <div className="mt-4">
              <div className="bg-gray-100 p-2 rounded">
                <h3 className="font-medium">Map Legend</h3>
                <div className="grid grid-cols-2 gap-2 mt-2">
                  <div className="flex items-center">
                    <div className="w-4 h-4 mr-2" style={{ backgroundColor: mapStyles.buildings.fillColor }}></div>
                    <span>Buildings</span>
                  </div>
                  <div className="flex items-center">
                    <div className="w-4 h-4 mr-2" style={{ backgroundColor: mapStyles.roads.color }}></div>
                    <span>Roads</span>
                  </div>
                  <div className="flex items-center">
                    <div className="w-4 h-4 mr-2" style={{ backgroundColor: mapStyles.water.fillColor }}></div>
                    <span>Water</span>
                  </div>
                  <div className="flex items-center">
                    <div className="w-4 h-4 mr-2" style={{ backgroundColor: mapStyles.vegetation.fillColor }}></div>
                    <span>Vegetation</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default MapSelector;