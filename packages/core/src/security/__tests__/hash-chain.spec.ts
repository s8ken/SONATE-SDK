import { HashChain } from '../hash-chain';

describe('HashChain', () => {
  let chain: HashChain;

  beforeEach(() => {
    chain = new HashChain();
  });

  describe('genesisHash', () => {
    it('should generate a consistent genesis hash for the same timestamp', () => {
      const ts = Date.now();
      jest.spyOn(Date, 'now').mockReturnValue(ts);
      const hash1 = chain.genesisHash('test');
      const hash2 = chain.genesisHash('test');
      expect(hash1).toBe(hash2);
      expect(typeof hash1).toBe('string');
      expect(hash1.length).toBeGreaterThan(0);
      jest.restoreAllMocks();
    });
  });

  describe('createLink', () => {
    it('should create a valid link', () => {
      const prev = 'GENESIS';
      const payload = 'test-payload';
      const link = chain.createLink(prev, payload);

      expect(link.previousHash).toBe(prev);
      expect(link.payload).toBe(payload);
      expect(link.hash).toBeDefined();
      expect(link.timestamp).toBeDefined();
      expect(chain.getLatestLink()).toEqual(link);
    });

    it('should maintain chain order', () => {
      const link1 = chain.createLink('GENESIS', '1');
      const link2 = chain.createLink(link1.hash, '2');

      const links = chain.getAllLinks();
      expect(links).toHaveLength(2);
      expect(links[0]).toEqual(link1);
      expect(links[1]).toEqual(link2);
    });
  });

  describe('verifyChain', () => {
    it('should verify a valid chain', () => {
      const genesis = chain.genesisHash('test');
      const link1 = chain.createLink(genesis, 'data1');
      const link2 = chain.createLink(link1.hash, 'data2');

      const result = chain.verifyEntireChain(genesis);
      expect(result.valid).toBe(true);
      expect(result.verifiedLinks).toBe(2);
      expect(result.issues).toHaveLength(0);
    });

    it('should detect tampered payload', () => {
      const genesis = chain.genesisHash('test');
      const link1 = chain.createLink(genesis, 'data1');
      const link2 = chain.createLink(link1.hash, 'data2');

      // Tamper with link1
      link1.payload = 'tampered';

      const result = chain.verifyEntireChain(genesis);
      expect(result.valid).toBe(false);
      expect(result.brokenAt).toBe(link1.hash);
      expect(result.issues.length).toBeGreaterThan(0);
    });

    it('should handle circular references', () => {
      const genesis = chain.genesisHash('test');
      const link1 = chain.createLink(genesis, 'data1');
      const link2 = chain.createLink(link1.hash, 'data2');

      // Create a cycle
      link1.previousHash = link2.hash;

      const result = chain.verifyEntireChain(genesis);
      expect(result.valid).toBe(false);
      expect(result.issues[0]).toMatch(/Circular reference/);
    });
  });

  describe('findLinks', () => {
    it('should find links by time range', () => {
      chain.createLink('GENESIS', 'old', 1000);
      chain.createLink('H1', 'mid', 2000);
      chain.createLink('H2', 'new', 3000);

      const found = chain.findLinksInTimeRange(1500, 2500);
      expect(found).toHaveLength(1);
      expect(found[0].payload).toBe('mid');
    });

    it('should find links by metadata', () => {
      chain.createLink('GENESIS', '1', Date.now(), undefined, { type: 'A' });
      chain.createLink('H1', '2', Date.now(), undefined, { type: 'B' });
      chain.createLink('H2', '3', Date.now(), undefined, { type: 'A', extra: true });

      const found = chain.findLinksByMetadata({ type: 'A' });
      expect(found).toHaveLength(2);
      expect(found[0].payload).toBe('1');
      expect(found[1].payload).toBe('3');
    });
  });

  describe('serialization', () => {
    it('should serialize and deserialize a link', () => {
      const link = chain.createLink('GENESIS', 'data', 123, 'sig', { meta: true });
      const json = HashChain.serializeLink(link);
      const restored = HashChain.deserializeLink(json);

      expect(restored).toEqual(link);
    });
  });

  describe('stats', () => {
    it('should calculate stats correctly', () => {
      chain.createLink('GENESIS', '1', 1000, 'sig1');
      chain.createLink('H1', '2', 2000, undefined, { meta: true });

      const stats = chain.getStats();
      expect(stats.totalLinks).toBe(2);
      expect(stats.earliestTimestamp).toBe(1000);
      expect(stats.latestTimestamp).toBe(2000);
      expect(stats.hasSignatures).toBe(true);
      expect(stats.hasMetadata).toBe(true);
      expect(stats.averageTimeBetweenLinks).toBe(1000);
    });

    it('should handle empty stats', () => {
      const stats = chain.getStats();
      expect(stats.totalLinks).toBe(0);
      expect(stats.earliestTimestamp).toBeNull();
    });
  });
});
