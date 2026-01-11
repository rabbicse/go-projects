import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

// Custom metrics
const ShortenDuration = new Trend('shorten_duration');
const RedirectDuration = new Trend('redirect_duration');
const ShortenSuccessRate = new Rate('shorten_success_rate');
const RedirectSuccessRate = new Rate('redirect_success_rate');

export const options = {
  stages: [
    { duration: '1m', target: 50 },    // Ramp up to 50 users
    { duration: '3m', target: 50 },    // Stay at 50 users
    { duration: '1m', target: 100 },   // Ramp up to 100 users
    { duration: '3m', target: 100 },   // Stay at 100 users
    { duration: '1m', target: 0 },     // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],  // 95% of requests < 500ms
    shorten_success_rate: ['rate>0.95'], // 95% success rate
    redirect_success_rate: ['rate>0.95'], // 95% success rate
  },
};

// Global variables
const BASE_URL = 'http://localhost';
let shortUrls = [];

export function setup() {
  // Warm up the system with some initial requests
  const warmupPayload = JSON.stringify({ url: 'https://example.com' });
  const warmupParams = {
    headers: { 'Content-Type': 'application/json' },
  };
  
  for (let i = 0; i < 10; i++) {
    const res = http.post(`${BASE_URL}/api/v1/shorten`, warmupPayload, warmupParams);
    if (res.status === 200) {
      const data = JSON.parse(res.body);
      shortUrls.push(data.short_url);
    }
    sleep(1);
  }
  
  return { shortUrls };
}

export default function (data) {
  // Test 1: Shorten URL (70% of requests)
  if (Math.random() < 0.7) {
    const payload = JSON.stringify({
      url: `https://example.com/${Math.random().toString(36).substring(7)}`,
    });
    
    const params = {
      headers: { 'Content-Type': 'application/json' },
    };
    
    const startTime = new Date().getTime();
    const res = http.post(`${BASE_URL}/api/v1/shorten`, payload, params);
    const duration = new Date().getTime() - startTime;
    
    ShortenDuration.add(duration);
    ShortenSuccessRate.add(res.status === 200);
    
    check(res, {
      'shorten status is 200': (r) => r.status === 200,
      'shorten returns short_url': (r) => {
        if (r.status === 200) {
          const data = JSON.parse(r.body);
          return data.short_url && data.short_url.includes('http');
        }
        return false;
      },
    });
    
    // Store successful short URLs for redirect testing
    if (res.status === 200) {
      const responseData = JSON.parse(res.body);
      data.shortUrls.push(responseData.short_url);
    }
  }
  
  // Test 2: Redirect (30% of requests)
  else if (data.shortUrls.length > 0) {
    const randomShortUrl = data.shortUrls[Math.floor(Math.random() * data.shortUrls.length)];
    
    const startTime = new Date().getTime();
    const res = http.get(randomShortUrl, { redirects: 0 }); // Don't follow redirects
    const duration = new Date().getTime() - startTime;
    
    RedirectDuration.add(duration);
    RedirectSuccessRate.add(res.status === 302 || res.status === 301);
    
    check(res, {
      'redirect status is 302/301': (r) => r.status === 302 || r.status === 301,
      'redirect has location header': (r) => r.headers.Location !== undefined,
    });
  }
  
  sleep(0.1); // Small delay between requests
}

export function teardown(data) {
  console.log(`Generated ${data.shortUrls.length} short URLs during test`);
}