"""Locators for the ADR-0027 sidebar shell, shared by every browser journey.

The h1 is the view name. The active organization is in the sidebar and breadcrumb. Refresh,
step-up, sign-out and the role list live in the user menu; the organization switcher changes
tenant as soon as an option is chosen.
"""
import re

from playwright.sync_api import expect

USER_BUTTON = re.compile(r'^Mi sesión')


def go_to(page, view):
    """Sidebar navigation: one public hash per view; the h1 becomes the view name."""
    page.get_by_role('navigation', name='Secciones').get_by_role('link', name=view, exact=True).click()
    expect(page.locator('h1')).to_have_text(view)


def in_tenant(page, name):
    expect(page.locator('.sb-org-name')).to_have_text(name)
    expect(page.locator('h1')).to_have_count(1)


def open_menu(page):
    user = page.get_by_role('button', name=USER_BUTTON)
    if user.get_attribute('aria-expanded') != 'true':
        user.click()
    expect(page.locator('#user-menu')).to_be_visible()


def close_menu(page):
    if page.get_by_role('button', name=USER_BUTTON).get_attribute('aria-expanded') == 'true':
        page.keyboard.press('Escape')
    expect(page.locator('#user-menu')).to_have_count(0)


def menu_action(page, name):
    open_menu(page)
    page.get_by_role('button', name=name, exact=True).click()


def switch_tenant(page, name):
    page.get_by_label('Cambiar de organización', exact=True).select_option(label=name)
    in_tenant(page, name)


def shows_role(page, label):
    """The user menu lists the roles of the active context."""
    open_menu(page)
    expect(page.locator('#user-menu')).to_contain_text(label)
    close_menu(page)
