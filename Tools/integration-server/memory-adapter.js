// In-memory adapter with a reset() so tests can wipe state via POST /test/reset.
const stores = new Map();

export function resetAdapters() {
  stores.clear();
}

export default class MemoryAdapter {
  constructor(name) {
    this.name = name;
    if (!stores.has(name)) stores.set(name, new Map());
  }

  get store() {
    if (!stores.has(this.name)) stores.set(this.name, new Map());
    return stores.get(this.name);
  }

  // Grant-id and user-code lookups scan the store; the data set is tiny in tests.
  #live(predicate) {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (entry.expiresAt && entry.expiresAt < now) {
        this.store.delete(key);
      } else if (predicate(entry.payload)) {
        return entry;
      }
    }
    return undefined;
  }

  async upsert(id, payload, expiresIn) {
    const previous = this.store.get(id);
    this.store.set(id, {
      payload: { ...payload, ...(previous?.payload.consumed ? { consumed: previous.payload.consumed } : {}) },
      expiresAt: expiresIn ? Date.now() + expiresIn * 1000 : undefined,
    });
  }

  async find(id) {
    const entry = this.store.get(id);
    if (!entry) return undefined;
    if (entry.expiresAt && entry.expiresAt < Date.now()) {
      this.store.delete(id);
      return undefined;
    }
    return entry.payload;
  }

  async findByUid(uid) {
    return this.#live((payload) => payload.uid === uid)?.payload;
  }

  async findByUserCode(userCode) {
    return this.#live((payload) => payload.userCode === userCode)?.payload;
  }

  async destroy(id) {
    this.store.delete(id);
  }

  async consume(id) {
    const entry = this.store.get(id);
    if (entry) entry.payload.consumed = Math.floor(Date.now() / 1000);
  }

  async revokeByGrantId(grantId) {
    for (const [key, entry] of this.store) {
      if (entry.payload.grantId === grantId) this.store.delete(key);
    }
  }
}
