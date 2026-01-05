/**
 * HubSpot Rate-Limited API Client
 *
 * Handles:
 * - Automatic rate limiting (max 4 requests/second = ~40/10 seconds)
 * - Retry logic with exponential backoff
 * - 429 rate limit error handling
 * - Request queuing (FIFO)
 */

import axios from 'axios';

// Configuration
const HUBSPOT_RATE_LIMIT = {
  maxRequestsPerSecond: 4,        // Conservative: 4 req/sec = 40 per 10-sec window
  maxRetries: 3,                   // Retry up to 3 times on rate limit
  defaultRetryDelayMs: 3000,       // Default wait time if no Retry-After header
  queueCheckIntervalMs: 250        // How often to process queue (4x per second)
};

class HubSpotRateLimitedClient {
  constructor(apiToken) {
    if (!apiToken) {
      throw new Error('HubSpot API token is required');
    }

    this.baseURL = 'https://api.hubapi.com';
    this.headers = {
      'Authorization': `Bearer ${apiToken}`,
      'Content-Type': 'application/json'
    };

    // Request queue
    this.queue = [];
    this.processing = false;
    this.requestTimestamps = []; // Track request times for rate limiting

    // Start queue processor
    this.startQueueProcessor();
  }

  async request(path, options = {}) {
    return new Promise((resolve, reject) => {
      this.queue.push({
        path,
        options,
        resolve,
        reject,
        retries: 0,
        addedAt: Date.now()
      });
    });
  }

  startQueueProcessor() {
    setInterval(() => {
      if (this.queue.length > 0 && !this.processing) {
        this.processNextRequest();
      }
    }, HUBSPOT_RATE_LIMIT.queueCheckIntervalMs);
  }

  canMakeRequest() {
    const now = Date.now();
    const oneSecondAgo = now - 1000;

    this.requestTimestamps = this.requestTimestamps.filter(ts => ts > oneSecondAgo);
    return this.requestTimestamps.length < HUBSPOT_RATE_LIMIT.maxRequestsPerSecond;
  }

  async processNextRequest() {
    if (this.queue.length === 0) return;

    if (!this.canMakeRequest()) {
      return;
    }

    this.processing = true;
    const job = this.queue.shift();

    try {
      this.requestTimestamps.push(Date.now());
      const result = await this.executeRequest(job);
      job.resolve(result);
    } catch (error) {
      if (this.isRateLimitError(error) && job.retries < HUBSPOT_RATE_LIMIT.maxRetries) {
        const retryDelay = this.getRetryDelay(error, job.retries);
        console.warn(`[HubSpot] Rate limited on ${job.path}, retrying in ${retryDelay}ms (attempt ${job.retries + 1}/${HUBSPOT_RATE_LIMIT.maxRetries})`);

        job.retries++;

        setTimeout(() => {
          this.queue.unshift(job);
        }, retryDelay);
      } else {
        if (this.isRateLimitError(error)) {
          console.error(`[HubSpot] Rate limit exceeded for ${job.path} after ${HUBSPOT_RATE_LIMIT.maxRetries} retries`);
        }
        job.reject(error);
      }
    } finally {
      this.processing = false;
    }
  }

  async executeRequest(job) {
    const { path, options } = job;
    const url = path.startsWith('http') ? path : `${this.baseURL}${path}`;

    const config = {
      method: options.method || 'GET',
      url,
      headers: { ...this.headers, ...(options.headers || {}) },
      timeout: options.timeout || 30000,
      ...(options.params && { params: options.params }),
      ...(options.data && { data: options.data })
    };

    const response = await axios(config);
    return response.data;
  }

  isRateLimitError(error) {
    if (!error.response) return false;

    if (error.response.status === 429) return true;

    const errorMessage = error.response.data?.message || '';
    const errorCategory = error.response.data?.category || '';

    return (
      errorMessage.includes('ten_secondly_rolling') ||
      errorMessage.includes('rate limit') ||
      errorCategory === 'RATE_LIMITS'
    );
  }

  getRetryDelay(error, retryCount) {
    const retryAfter = error.response?.headers['retry-after'];
    if (retryAfter) {
      const seconds = parseInt(retryAfter, 10);
      if (!isNaN(seconds)) {
        return seconds * 1000;
      }
    }

    return HUBSPOT_RATE_LIMIT.defaultRetryDelayMs * Math.pow(2, retryCount);
  }

  async get(path, params = {}) {
    return this.request(path, { method: 'GET', params });
  }

  async post(path, data = {}, params = {}) {
    return this.request(path, { method: 'POST', data, params });
  }

  async put(path, data = {}) {
    return this.request(path, { method: 'PUT', data });
  }

  async patch(path, data = {}) {
    return this.request(path, { method: 'PATCH', data });
  }

  async delete(path) {
    return this.request(path, { method: 'DELETE' });
  }

  getQueueStats() {
    return {
      queueLength: this.queue.length,
      processing: this.processing,
      recentRequestCount: this.requestTimestamps.length,
      oldestQueuedRequest: this.queue.length > 0
        ? Date.now() - this.queue[0].addedAt
        : 0
    };
  }
}

export default HubSpotRateLimitedClient;
