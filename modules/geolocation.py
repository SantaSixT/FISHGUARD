import requests
import folium

def get_ip_location(ip):
    """Interroge une API pour obtenir les coordonnées GPS d'une IP"""
    try:
        # API gratuite (limitée à 45 requêtes/minute, suffisant pour nous)
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=5)
        data = response.json()
        
        if data['status'] == 'success':
            return {
                "ip": ip,
                "lat": data['lat'],
                "lon": data['lon'],
                "country": data['country'],
                "city": data['city'],
                "isp": data['isp']
            }
    except Exception:
        pass
    return None

def generate_map(ip_data_list):
    """Génère une carte Folium avec les points trouvés"""
    if not ip_data_list:
        return None

    # On centre la carte sur le premier point trouvé
    first_loc = ip_data_list[0]
    m = folium.Map(location=[first_loc['lat'], first_loc['lon']], zoom_start=2)

    for loc in ip_data_list:
        folium.Marker(
            [loc['lat'], loc['lon']],
            popup=f"{loc['city']}, {loc['country']} ({loc['ip']})",
            tooltip=loc['isp'],
            icon=folium.Icon(color="red", icon="warning-sign")
        ).add_to(m)
        
    return m