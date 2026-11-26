# Bee Monitor

WordPress security monitoring plugin: detects suspicious PHP file changes, WordPress core tampering, and risky admin, user, and settings changes, then emails clear, deduplicated alerts. Read-only: it never deletes, quarantines, or modifies files.

The user-facing documentation is in [`readme.txt`](readme.txt) (the WordPress.org format).

## Requirements

WordPress 6.5+, PHP 7.4+.

## Development

```bash
composer install        # coding-standards tooling (dev only, not shipped)
composer run lint       # PHP syntax check
composer run phpcs      # WordPress Coding Standards + PHP 7.4+ compatibility
composer run build      # dist/bee-monitor-<version>.zip, excluding files in .distignore
```

Run the official [Plugin Check](https://wordpress.org/plugins/plugin-check/) against the built folder before every release. CI does this on each push.

## Releasing

1. Bump the version in three places: the `Version:` header and `BEE_MONITOR_VERSION` in `bee-monitor.php`, and `Stable tag:` in `readme.txt`. Add a changelog entry. `bin/build-zip.sh` refuses to build if they differ.
2. Commit, then tag with the bare version number: `git tag 1.0.1 && git push origin main --tags`.
3. The deploy workflow publishes the tag to WordPress.org SVN and attaches the zip to a GitHub release.

WordPress.org banners, icons, and screenshots go in `.wordpress-org/` (deployed to the SVN `assets` folder).

## License

GPL-2.0-or-later. See the plugin header and `readme.txt`.
