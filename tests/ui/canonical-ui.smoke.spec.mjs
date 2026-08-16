import { test, expect } from '@playwright/test';
import { loadModel } from '../../scripts/ui-model-tools.mjs';
import { createFixtureState } from '../../scripts/ui-test-fixtures.mjs';
import { evidenceRecord } from '../../scripts/ui-evidence-tools.mjs';

const { model } = await loadModel(process.cwd());
const fixtures = createFixtureState();
const executable = model.interactions.filter((interaction) => interaction.verification);

for (const interaction of executable) {
  test(interaction.verification.test_id, async ({ page, browserName }, testInfo) => {
    const { verification } = interaction;
    const failures = [];
    page.on('pageerror', (error) => failures.push(error.message));
    await page.goto(verification.route);
    for (const step of verification.steps) {
      const locator = page.locator(step.selector);
      if (step.action === 'fill_fixture') await locator.fill(step.fixture_value.split('.').reduce((value, key) => value[key], fixtures));
      if (step.action === 'click') await locator.click();
      if (step.action === 'check') await locator.check();
      if (step.action === 'expect_count') await expect(locator).toHaveCount(Number(step.value));
      if (step.action === 'expect_visible') await expect(locator).toBeVisible();
      if (step.action === 'expect_text') await expect(locator).toContainText(step.value);
      if (step.action === 'expect_not_text') await expect(locator).not.toContainText(step.value);
    }
    expect(failures).toEqual([]);
    await testInfo.attach('redacted-evidence.json', { body: JSON.stringify(evidenceRecord({ test_id: verification.test_id, result: 'PASSED', details: { interaction: interaction.id, capabilities: interaction.capability_ids, browser: browserName }, limitations: ['local fixture only'] }), null, 2), contentType: 'application/json' });
  });
}
