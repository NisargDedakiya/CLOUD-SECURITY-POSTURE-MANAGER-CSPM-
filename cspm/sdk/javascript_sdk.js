/**
 * Aegis JavaScript/TypeScript SDK (`@aegis/cnapp-sdk`)
 */

class AegisClient {
  constructor(apiKey, endpoint = 'http://localhost:8000') {
    this.apiKey = apiKey;
    this.endpoint = endpoint.replace(/\/$/, '');
  }

  async getHeaders() {
    return {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.apiKey}`
    };
  }

  async listFindings(status = 'open') {
    const res = await fetch(`${this.endpoint}/api/v1/cspm/findings?status=${status}`, {
      headers: await this.getHeaders()
    });
    return res.json();
  }

  async triggerScan(accountId) {
    const res = await fetch(`${this.endpoint}/api/v1/cspm/accounts/${accountId}/scan`, {
      method: 'POST',
      headers: await this.getHeaders()
    });
    return res.json();
  }
}

if (typeof module !== 'undefined') {
  module.exports = { AegisClient };
}
