export function load() {
    return fetch("/api/v1/profile/me").then(r => r.json());
}
const SEGMENT = "sk_test_abcdefghijklmnopqrstuvwx";