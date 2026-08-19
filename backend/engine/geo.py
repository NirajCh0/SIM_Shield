"""
Offline geography helpers: coarse area labels and distance bands.

WHY THIS EXISTS
SIMShield's privacy policy forbids storing raw coordinates
(`compliance.yaml -> privacy.drop_raw_location_after_scoring`). But a
subscriber genuinely benefits from seeing *where* their account was signed into
— "was that me in Pokhara last Tuesday?" is exactly the question that catches a
takeover early.

The compromise implemented here: reduce a precise fix to a **coarse area label
plus a distance band** before anything is persisted. "27.7154, 85.3123" becomes
"Kathmandu, Nepal · under 5 km from a safe zone". That is informative enough for
a human to spot an impostor, but far too coarse to track someone's movements —
so the feature can exist without the app becoming a location history.

The gazetteer is deliberately small and local: no geocoding service is called,
so this works offline (the PWA needs that) and no coordinates ever leave the
machine.
"""
import math

# name, country, lat, lon — public places, used only as reference points.
GAZETTEER = [
    # Kathmandu Valley
    ("Thamel, Kathmandu", "Nepal", 27.7154, 85.3123),
    ("New Road, Kathmandu", "Nepal", 27.7017, 85.3106),
    ("Boudha, Kathmandu", "Nepal", 27.7215, 85.3620),
    ("Kalanki, Kathmandu", "Nepal", 27.6933, 85.2816),
    ("Patan, Lalitpur", "Nepal", 27.6766, 85.3250),
    ("Pulchowk, Lalitpur", "Nepal", 27.6795, 85.3168),
    ("Bhaktapur", "Nepal", 27.6722, 85.4298),
    ("Kirtipur", "Nepal", 27.6786, 85.2770),
    # rest of Nepal
    ("Pokhara", "Nepal", 28.2096, 83.9588),
    ("Chitwan", "Nepal", 27.5291, 84.3542),
    ("Butwal", "Nepal", 27.7000, 83.4486),
    ("Biratnagar", "Nepal", 26.4525, 87.2718),
    ("Birgunj", "Nepal", 27.0104, 84.8821),
    ("Nepalgunj", "Nepal", 28.0500, 81.6167),
    ("Dharan", "Nepal", 26.8065, 87.2846),
    ("Janakpur", "Nepal", 26.7288, 85.9266),
    ("Ilam", "Nepal", 26.9096, 87.9285),
    ("Jomsom", "Nepal", 28.7808, 83.7228),
    # abroad — common destinations for Nepali subscribers, plus demo points
    ("Delhi", "India", 28.6139, 77.2090),
    ("Kolkata", "India", 22.5726, 88.3639),
    ("Doha", "Qatar", 25.2854, 51.5310),
    ("Dubai", "UAE", 25.2048, 55.2708),
    ("Kuala Lumpur", "Malaysia", 3.1390, 101.6869),
    ("Seoul", "South Korea", 37.5665, 126.9780),
    ("Moscow", "Russia", 55.7558, 37.6173),
    ("Lagos", "Nigeria", 6.5244, 3.3792),
    ("London", "UK", 51.5074, -0.1278),
]


def haversine_km(a_lat, a_lon, b_lat, b_lon) -> float:
    """Great-circle distance in kilometres."""
    r = 6371.0
    p1, p2 = math.radians(a_lat), math.radians(b_lat)
    dp = math.radians(b_lat - a_lat)
    dl = math.radians(b_lon - a_lon)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def nearest_place(lat, lon) -> dict:
    """Closest gazetteer entry to a coordinate, with how far off it is."""
    best, best_km = None, float("inf")
    for name, country, plat, plon in GAZETTEER:
        km = haversine_km(lat, lon, plat, plon)
        if km < best_km:
            best, best_km = (name, country), km
    name, country = best
    return {"place": name, "country": country, "km_from_place": round(best_km, 1)}


def distance_band(km) -> str:
    """Coarsen a distance into a band — never a precise figure."""
    if km is None:
        return "unknown"
    if km < 5:
        return "under 5 km"
    if km < 25:
        return "5–25 km"
    if km < 100:
        return "25–100 km"
    if km < 500:
        return "100–500 km"
    if km < 2000:
        return "500–2,000 km"
    return "over 2,000 km"


def coarse_area(lat, lon, safe_zones=None) -> dict:
    """
    Reduce a precise fix to what may be stored: an area label, the country, and
    a band for how far it sits from the user's nearest safe zone. Raw
    coordinates are NOT part of the return value by design.
    """
    if lat is None or lon is None:
        return {"area": "unknown", "country": None, "band": "unknown",
                "far_from_safe_zones": False}
    near = nearest_place(lat, lon)
    # If the fix is far from every gazetteer entry, don't invent precision.
    area = near["place"] if near["km_from_place"] <= 120 else f"near {near['place']}"

    band, far = "unknown", False
    if safe_zones:
        km = min(haversine_km(lat, lon, z["lat"], z["lon"]) for z in safe_zones)
        band = distance_band(km)
        far = km >= 100
    return {"area": area, "country": near["country"], "band": band,
            "far_from_safe_zones": far}
