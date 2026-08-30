# Inovix Development Setup
## Overview

This document provides the initial development setup guidance for the Inovix project.

Because the project's final technology stack and implementation details are still under development, some setup instructions are intentionally marked as To Be Finalized (TBD).

This document should be updated as the development team confirms the technologies, dependencies, and component-specific setup requirements.


## Required Tools
The exact development tools and dependencies may vary depending on the final technology stack selected for each component.

At a minimum, developers may require:

- Git for version control
- A GitHub account with access to the Inovix repository
- A suitable code editor or IDE, such as Visual Studio Code
- The required runtime, package manager, or framework tools for the component being developed

Additional tools and version requirements should be documented once the technology stack for each component is finalized.

*Status: To Be Finalized (TBD)*


## Repository Setup

Developers should work from a local copy of the Inovix repository.

The general setup process is:

1. Ensure that Git is installed on the local system.
2. Obtain access to the Inovix GitHub repository.
3. Clone the repository to the local machine.
4. Open the cloned project folder in a suitable code editor or IDE.
5. Review the project structure and the documentation relevant to the component being developed.

The exact repository URL and any additional access requirements should be provided by the project team.

*Status: To Be Finalized (TBD)*


## Cloning the Repository

After obtaining access to the Inovix repository, developers can create a local copy using Git.

*The general command is:*
git clone <https://github.com/Inovix-Security-Team/inovix>

After cloning, move into the project directory:
cd inovix

*Example workflow:*
git clone https://github.com/Inovix-Security-Team/inovix
cd inovix

Developers should confirm that the repository has been cloned successfully before creating or modifying project files.

**Status: Repository URL To Be Added**


## Branch Workflow

Developers should avoid making changes directly to the main branch unless the team has explicitly agreed otherwise.

The general branch workflow is:

1. Update the local repository.
2. Create a separate branch for the task or feature.
3. Make the required changes.
4. Review and test the changes where applicable.
5. Commit the changes with a clear commit message.
6. Push the branch to the remote repository.
7. Create a Pull Request for review and merging.

*A general example is:*

git checkout main
git pull
git checkout -b <branch-name>
git add .
git commit -m "<clear-commit-message>"
git push -u origin <branch-name>

Branch naming conventions and review requirements should follow the workflow agreed upon by the Inovix development team.

**Status: Team Workflow To Be Finalized**



## Running Project Components

The exact commands required to run each Inovix component will depend on the technologies and frameworks selected during development.

The repository currently contains multiple project components, including:

- Frontend
- Backend
- Security Engine
- Browser Extension
- Supporting scripts and tests

Before running a component, developers should review the component-specific documentation and configuration files.

The general process is expected to be:

1. Navigate to the relevant component directory.
2. Install the required dependencies.
3. Configure any required environment variables or local settings.
4. Run the component using the appropriate development command.
5. Verify that the component starts and operates as expected.

Component-specific setup and run commands should be documented as the implementation and technology stack are finalized.

*Status: To Be Finalized (TBD)*



## Development Guidelines
When working on the Inovix project, developers should follow the agreed project workflow and keep changes limited to the relevant task or component.

General development guidelines include:

- Work on a separate branch for a specific task or feature.
- Avoid making unrelated changes in the same task or commit.
- Keep commit messages clear and meaningful.
- Review changes before committing them.
- Test changes where applicable before creating a Pull Request.
- Document important setup requirements, configuration changes, or technical decisions.
- Avoid introducing unapproved technologies, integrations, or architectural changes without team discussion.

Additional development standards and contribution guidelines may be documented as the project evolves.

*Status: To Be Finalized (TBD)*




## Document Status
This document provides the initial development setup foundation for the Inovix project.

It currently describes the general requirements for setting up the repository, cloning the project, working with branches, and preparing project components for development.

Component-specific technologies, dependencies, configuration steps, environment variables, and run commands should be added as they are finalized by the development team.

This document should be kept up to date whenever the development workflow or project setup requirements change.

