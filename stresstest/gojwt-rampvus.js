import http from "k6/http";
import { Rate } from "k6/metrics";

// Custom metrics (reduce noise metrics)
const not_200 = new Rate("not_200"); // responses != 200 (does not include network errors)
const net_err = new Rate("net_err"); // status == 0 (timeout/connect/etc.)

const TARGET_URL = __ENV.TARGET_URL;
const TOKEN_SIZE = parseInt(__ENV.TOKEN_SIZE || "60000", 10);
const REQ_TIMEOUT = __ENV.REQ_TIMEOUT || "2s";

// Large JWT-like token, same for all VUs/iterations
const token = ".".repeat(TOKEN_SIZE);

const params = {
  headers: {
    Authorization: `Bearer ${token}`,
  },
  timeout: REQ_TIMEOUT,
};

export const options = {
  discardResponseBodies: true,

  scenarios: {
    breakpoint_vus: {
      executor: "ramping-vus",
      startVUs: 0,

      // Plan: warm-up -> growth stages -> flat on each stage -> decline
      // Change targets under container (mem_limit/cpu/pids) and experiment goal
      stages: [
        // Warm-up (15s)
        { duration: "5s", target: 10 },
        { duration: "10s", target: 10 },

        // Big steps + short holds
        { duration: "10s", target: 50 },
        { duration: "15s", target: 50 },

        { duration: "10s", target: 100 },
        { duration: "15s", target: 100 },

        { duration: "10s", target: 150 },
        { duration: "15s", target: 150 },

        // Expected saturation start
        { duration: "10s", target: 250 },
        { duration: "20s", target: 250 },

        { duration: "10s", target: 350 },
        { duration: "20s", target: 350 },

        // Ramp down
        { duration: "10s", target: 0 },
      ],

      // In closed model it is important to behavior when VU is declining:
      // gracefulRampDown=0s => VUs will be removed quickly (may break some iterations)
      gracefulRampDown: "0s",

      // Total stop of scenario after completing stages
      gracefulStop: "0s",
    },
  },

  thresholds: {
    http_req_failed: ["rate<0.50"],
    net_err: ["rate<0.50"],
    not_200: ["rate<0.50"],
  },

  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "p(99)", "max"],
};

export default function () {
  // Closed model: each VU makes "maximum fast" iterations
  // This is good for finding breakpoint by heap/GC: when degradation of throughput itself will fall
  const res = http.get(TARGET_URL, params);

  net_err.add(res.status === 0);

  if (res.status !== 0) {
    not_200.add(res.status !== 200);
  }
}
