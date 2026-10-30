# Contributing

When contributing to this repository, please first discuss the change you wish to make via issue,
email, or any other method with the owners of this repository before making a change. 

Please note we have a code of conduct, please follow it in all your interactions with the project.

## Pull Request Process

1. Ensure any install or build dependencies are removed before the end of the layer when doing a 
   build.
2. Update the README.md with details of changes to the interface, this includes new environment 
   variables, exposed ports, useful file locations and container parameters.
3. Increase the version numbers in any examples files and the README.md to the new version that this
   Pull Request would represent. The versioning scheme we use is [SemVer](http://semver.org/).
4. You may merge the Pull Request in once you have the sign-off of two other developers, or if you 
   do not have permission to do that, you may request the second reviewer to merge it for you.

## Development workflow

### Setting up

```shell
poetry install            # resolves dependencies and writes poetry.lock
poetry run grapheneX --validate
```

The hardening engine (`graphenex/core/hrd/`) and the tests use only the Python
standard library, so you can also run everything with a plain interpreter:

```shell
python -m unittest discover -s tests -t . -v
python -m graphenex --list --json
```

### Adding or changing a module

Every module must have:

* `name`, `desc`, `command`, `check` and `target_os`;
* a `revert` command **or** `files` snapshots (or an explicit, justified
  `irreversible` declaration);
* `cis` and `nist` control identifiers;
* `shell: true` if and only if the command needs a shell (pipes, redirects,
  `&&`);
* a test run of all four operations before you open the PR:

```shell
python -m graphenex --validate
python -m graphenex --apply <namespace/Module> --dry-run
sudo python -m graphenex --apply <namespace/Module>
python -m graphenex --check <namespace/Module>
sudo python -m graphenex --revert last
python -m graphenex --check <namespace/Module>      # drift again = revert worked
```

See [docs/modules.md](docs/modules.md) for the schema and authoring rules. A PR
that adds a module without an audit or revert path will not be merged.

### Security expectations

* Never add `shell=True` to the executor or bypass `graphenex/core/hrd/exec.py`.
* Never build HTML from strings in the web UI; use DOM APIs and `.text()`.
* Do not log secrets, tokens or file contents that may contain credentials.
* New web events must be wrapped in `@auth_socketio` and validate their payload.
* Keep the loopback default; document any new environment variable in the README.
* If you touch the web layer or the executor, add or update tests in `tests/`.

### Review checklist

* [ ] `python -m unittest discover -s tests -t .` passes
* [ ] `python -m graphenex --validate` reports 0 errors
* [ ] Documentation updated (`README.md`, `docs/`)
* [ ] Security implications considered and, when relevant, noted in
      `docs/security-review.md`

## Code of Conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we as
contributors and maintainers pledge to making participation in our project and
our community a harassment-free experience for everyone, regardless of age, body
size, disability, ethnicity, gender identity and expression, level of experience,
nationality, personal appearance, race, religion, or sexual identity and
orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment
include:

* Using welcoming and inclusive language
* Being respectful of differing viewpoints and experiences
* Gracefully accepting constructive criticism
* Focusing on what is best for the community
* Showing empathy towards other community members

Examples of unacceptable behavior by participants include:

* The use of sexualized language or imagery and unwelcome sexual attention or
advances
* Trolling, insulting/derogatory comments, and personal or political attacks
* Public or private harassment
* Publishing others' private information, such as a physical or electronic
  address, without explicit permission
* Other conduct which could reasonably be considered inappropriate in a
  professional setting

### Our Responsibilities

Project maintainers are responsible for clarifying the standards of acceptable
behavior and are expected to take appropriate and fair corrective action in
response to any instances of unacceptable behavior.

Project maintainers have the right and responsibility to remove, edit, or
reject comments, commits, code, wiki edits, issues, and other contributions
that are not aligned to this Code of Conduct, or to ban temporarily or
permanently any contributor for other behaviors that they deem inappropriate,
threatening, offensive, or harmful.

### Scope

This Code of Conduct applies both within project spaces and in public spaces
when an individual is representing the project or its community. Examples of
representing a project or community include using an official project e-mail
address, posting via an official social media account, or acting as an appointed
representative at an online or offline event. Representation of a project may be
further defined and clarified by project maintainers.

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be
reported by contacting the project team at graphenex.project@protonmail.com. All
complaints will be reviewed and investigated and will result in a response that
is deemed necessary and appropriate to the circumstances. The project team is
obligated to maintain confidentiality with regard to the reporter of an incident.
Further details of specific enforcement policies may be posted separately.

Project maintainers who do not follow or enforce the Code of Conduct in good
faith may face temporary or permanent repercussions as determined by other
members of the project's leadership.

### Attribution

This Code of Conduct is adapted from the [Contributor Covenant][homepage], version 1.4,
available at [http://contributor-covenant.org/version/1/4][version]

[homepage]: http://contributor-covenant.org
[version]: http://contributor-covenant.org/version/1/4/
