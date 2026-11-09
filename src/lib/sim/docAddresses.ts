/**
 * Documentation addresses (RFC 5737) that stand for real-world networks in the Live Feed (R5,
 * docs/LOG-REALISM-STANDARD.md). The feed's attacker, hosting, VPN and home addresses used to be real
 * third-party IPs; they are now documentation addresses, and this table keeps what each one stood
 * for: where it geolocates and who runs the network (a Tor exit, a commercial VPN). Every geo and
 * network lookup asks here first (resolveGeo knownGeoForIp, _identity-common asnOf), so a sign-in
 * from a Tor exit still reads as a Tor exit in Frankfurt.
 */
/** Same shape as @/lib/geo/resolveGeo GeoPoint (kept here so resolveGeo can import this table). */
export interface DocPlace { country: string; city: string; lat: number; lon: number }

export interface DocOwner { asn: number; asOrg: string; isp: string; domain: string; anonymous: boolean }

export const DOC_ADDRESS_PLACES: Record<string, DocPlace> = {
  "198.51.100.11": { country: "France", city: "Paris", lat: 48.8, lon: 2.3 },
  "198.51.100.29": { country: "India", city: "Bangalore", lat: 12.9, lon: 77.6 },
  "198.51.100.38": { country: "France", city: "Paris", lat: 48.8, lon: 2.3 },
  "198.51.100.51": { country: "Russia", city: "Moscow", lat: 55.7, lon: 37.6 },
  "198.51.100.58": { country: "Nigeria", city: "Lagos", lat: 6.5, lon: 3.4 },
  "198.51.100.60": { country: "Ukraine", city: "Kyiv", lat: 50.4, lon: 30.5 },
  "198.51.100.87": { country: "Netherlands", city: "Amsterdam", lat: 52.3, lon: 4.9 },
  "198.51.100.93": { country: "Netherlands", city: "Amsterdam", lat: 52.3, lon: 4.9 },
  "198.51.100.95": { country: "Netherlands", city: "Amsterdam", lat: 52.3, lon: 4.9 },
  "198.51.100.97": { country: "Ukraine", city: "Kyiv", lat: 50.4, lon: 30.5 },
  "198.51.100.99": { country: "Netherlands", city: "Amsterdam", lat: 52.3, lon: 4.9 },
  "198.51.100.103": { country: "Netherlands", city: "Amsterdam", lat: 52.3, lon: 4.9 },
  "198.51.100.106": { country: "Netherlands", city: "Amsterdam", lat: 52.3, lon: 4.9 },
  "198.51.100.109": { country: "Russia", city: "Moscow", lat: 55.7, lon: 37.6 },
  "198.51.100.118": { country: "Russia", city: "Moscow", lat: 55.7, lon: 37.6 },
  "198.51.100.129": { country: "Russia", city: "Moscow", lat: 55.7, lon: 37.6 },
  "198.51.100.136": { country: "Russia", city: "Moscow", lat: 55.7, lon: 37.6 },
  "198.51.100.157": { country: "Netherlands", city: "Amsterdam", lat: 52.3, lon: 4.9 },
  "198.51.100.199": { country: "Netherlands", city: "Amsterdam (DigitalOcean)", lat: 52.3, lon: 4.9 },
  "198.51.100.203": { country: "Russia", city: "Moscow", lat: 55.7, lon: 37.6 },
  "198.51.100.211": { country: "Netherlands", city: "Amsterdam", lat: 52.3, lon: 4.9 },
  "198.51.100.213": { country: "Netherlands", city: "Amsterdam", lat: 52.3, lon: 4.9 },
  "198.51.100.214": { country: "Netherlands", city: "Amsterdam (DigitalOcean)", lat: 52.3, lon: 4.9 },
  "198.51.100.218": { country: "Netherlands", city: "Amsterdam", lat: 52.3, lon: 4.9 },
  "198.51.100.227": { country: "Russia", city: "Moscow", lat: 55.7, lon: 37.6 },
  "198.51.100.231": { country: "France", city: "Paris", lat: 48.8, lon: 2.3 },
  // Own attacker addresses given to storylines that shared one (investigability "reuse"); they keep the
  // Amsterdam hosting hub their old 203.0.113.0-63 address had.
  "203.0.113.108": { country: "Netherlands", city: "Amsterdam", lat: 52.37, lon: 4.9 },
  "203.0.113.109": { country: "Netherlands", city: "Amsterdam", lat: 52.37, lon: 4.9 },
  "203.0.113.111": { country: "Netherlands", city: "Amsterdam", lat: 52.37, lon: 4.9 },
  "203.0.113.115": { country: "Netherlands", city: "Amsterdam", lat: 52.37, lon: 4.9 },
  "203.0.113.121": { country: "Netherlands", city: "Amsterdam", lat: 52.37, lon: 4.9 },
};

export const DOC_ADDRESS_OWNERS: Record<string, DocOwner> = {
  "198.51.100.50": { asn: 9009, asOrg: "m247 europe srl", isp: "m247 ltd", domain: "m247.com", anonymous: true },
  "198.51.100.76": { asn: 212238, asOrg: "datacamp limited", isp: "datacamp limited", domain: "datacamp.co.uk", anonymous: true },
  "198.51.100.87": { asn: 60729, asOrg: "stiftung erneuerbare freiheit", isp: "tor exit node", domain: "torservers.net", anonymous: true },
  "198.51.100.93": { asn: 60729, asOrg: "stiftung erneuerbare freiheit", isp: "tor exit node", domain: "torservers.net", anonymous: true },
  "198.51.100.95": { asn: 60729, asOrg: "stiftung erneuerbare freiheit", isp: "tor exit node", domain: "torservers.net", anonymous: true },
  "198.51.100.99": { asn: 60729, asOrg: "stiftung erneuerbare freiheit", isp: "tor exit node", domain: "torservers.net", anonymous: true },
  "198.51.100.103": { asn: 60729, asOrg: "stiftung erneuerbare freiheit", isp: "tor exit node", domain: "torservers.net", anonymous: true },
  "198.51.100.106": { asn: 60729, asOrg: "stiftung erneuerbare freiheit", isp: "tor exit node", domain: "torservers.net", anonymous: true },
  "198.51.100.157": { asn: 60729, asOrg: "stiftung erneuerbare freiheit", isp: "tor exit node", domain: "torservers.net", anonymous: true },
  "198.51.100.211": { asn: 60729, asOrg: "stiftung erneuerbare freiheit", isp: "tor exit node", domain: "torservers.net", anonymous: true },
  "198.51.100.213": { asn: 60729, asOrg: "stiftung erneuerbare freiheit", isp: "tor exit node", domain: "torservers.net", anonymous: true },
  "198.51.100.218": { asn: 60729, asOrg: "stiftung erneuerbare freiheit", isp: "tor exit node", domain: "torservers.net", anonymous: true },
};

/** Who runs the network of a documentation address that stands for a known operator. */
export function docOwnerOfIp(ip?: string | null): DocOwner | undefined {
  return ip ? DOC_ADDRESS_OWNERS[ip] : undefined;
}
