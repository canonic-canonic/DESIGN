/**
 * GATEWAY — OpenAI-compatible model routing, bakeoff, responses shim.
 * GOV: TALK/CANON.md
 */

export { envForLane, laneProviderFromHostname, requireGatewayKey, checkGatewayKey } from './registry.js';
export { oaiModels, oaiChatCompletions, oaiResponses } from './dispatch.js';
export { oaiBakeoff } from './bakeoff.js';
