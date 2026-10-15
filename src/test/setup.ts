import '@testing-library/jest-dom';

// Polyfill window.__TAURI_INTERNALS__ if needed
(window as any).__TAURI_INTERNALS__ = (window as any).__TAURI_INTERNALS__ || {};
