import { test, expect } from '@playwright/test'

test.beforeEach(async ({ page }) => {
  await page.goto('/')
})

test('app loads the wizard with workflow steps', async ({ page }) => {
  await expect(page.locator('ix-application-header')).toBeVisible()
  await expect(page.locator('ix-workflow-steps')).toBeVisible()
  await expect(page.getByText('Choose Action', { exact: true })).toBeVisible()
})

test('no action pre-selected and Next disabled', async ({ page }) => {
  const cards = page.locator('ix-action-card')
  await expect(cards).toHaveCount(2)
  for (const card of await cards.all()) {
    await expect(card).toHaveAttribute('aria-checked', 'false')
  }
  await expect(page.locator('ix-button', { hasText: 'Next' })).toHaveAttribute('disabled', '')
})

test('choosing an action and pressing Next opens the upload step', async ({ page }) => {
  await page.locator('ix-action-card[data-value="sign"]').click()
  await page.locator('ix-button', { hasText: 'Next' }).click()
  await expect(page.getByText('Select Files', { exact: true })).toBeVisible()
  await expect(page.locator('ix-upload')).toBeVisible()
})

test('dashboard view loads', async ({ page }) => {
  await page.goto('/#dashboard')
  await expect(page.getByText('Analytics & Metrics', { exact: true })).toBeVisible()
})

test('navigation between views via the menu', async ({ page }) => {
  await page.locator('ix-menu-item', { hasText: 'Analytics' }).click()
  await expect(page.getByText('Analytics & Metrics', { exact: true })).toBeVisible()
  await expect(page).toHaveURL(/#dashboard$/)
  await page.locator('ix-menu-item', { hasText: 'Sign / Verify' }).click()
  await expect(page.getByText('Choose Action', { exact: true })).toBeVisible()
})
