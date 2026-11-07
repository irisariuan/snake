import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseDevice, summary } from './device.js';

test('parseDevice normalizes and rejects', () => {
  assert.deepEqual(parseDevice(' AA-BB-CC-00-11-22 '), { value: 'aa:bb:cc:00:11:22' });
  assert.deepEqual(parseDevice('10.6.0.2'), { value: '10.6.0.2' });
  assert.deepEqual(parseDevice('10.8.0.0/24'), { value: '10.8.0.0/24' });
  assert.deepEqual(parseDevice('FD00::2'), { value: 'fd00::2' });
  for (const bad of ['', 'phone', '10.0.0.300', '10.0.0.0/33', 'fd00::/129', 'aa:bb:cc:dd:ee', '10.0.0.1/24/1']) {
    assert.ok(parseDevice(bad).error, bad);
  }
});

test('summary says who the policy applies to', () => {
  const s = (include, exclude, allowExclude = true) => summary({ include, exclude, allowExclude, emptyMeaning: 'every device', noun: 'This policy' });
  assert.equal(s([], []), 'This policy applies to every device.');
  assert.equal(s([], ['aa:bb:cc:00:00:01']), 'This policy applies to every device except 1 device.');
  assert.equal(s(['group:kids', 'aa:bb:cc:00:00:01', '10.6.0.2'], []), 'This policy applies only to 2 devices and 1 group.');
  assert.equal(s(['group:kids'], ['aa:bb:cc:00:00:09']), 'This policy applies only to 1 group, minus 1 device excluded.');
  const g = (include) => summary({ include, exclude: [], allowExclude: false, emptyMeaning: 'no devices yet', noun: 'This group' });
  assert.equal(g([]), 'This group has no devices yet.');
  assert.equal(g(['aa:bb:cc:00:00:01', 'aa:bb:cc:00:00:02']), 'This group has 2 devices.');
});
