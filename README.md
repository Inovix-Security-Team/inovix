# Inovix Frontend

## Overview

The Inovix frontend is the user interface of the Inovix security analysis platform.

This frontend provides a reusable UI/UX component system that can be used across different parts of the application, such as:

* Dashboard
* Analysis Results
* History
* Browser Extension UI
* Security Status Displays
* Risk and Severity Information

The main goal of this frontend foundation is to keep the application:

* Simple
* Consistent
* Reusable
* Easy to maintain
* Easy for other developers to extend

---

## UI/UX Foundation

The frontend contains reusable components instead of creating separate styles for every page.

The main reusable components include:

* Button
* Card
* Input
* Navbar
* Alert
* Loading Indicator
* Error Message
* Result Card
* Risk Badge
* Status Indicator
* Severity Badge

These components can be reused by other frontend developers while building application pages.

---

## Project Structure

```text
frontend/
│
├── public/
│
├── src/
│   │
│   ├── assets/
│   │
│   ├── components/
│   │   │
│   │   ├── Alert/
│   │   │   ├── Alert.jsx
│   │   │   └── Alert.css
│   │   │
│   │   ├── Button/
│   │   │   ├── Button.jsx
│   │   │   └── Button.css
│   │   │
│   │   ├── Card/
│   │   │   ├── Card.jsx
│   │   │   └── Card.css
│   │   │
│   │   ├── ErrorMessage/
│   │   │   ├── ErrorMessage.jsx
│   │   │   └── ErrorMessage.css
│   │   │
│   │   ├── Input/
│   │   │   ├── Input.jsx
│   │   │   └── Input.css
│   │   │
│   │   ├── LoadingIndicator/
│   │   │   ├── LoadingIndicator.jsx
│   │   │   └── LoadingIndicator.css
│   │   │
│   │   ├── Navbar/
│   │   │   ├── Navbar.jsx
│   │   │   └── Navbar.css
│   │   │
│   │   ├── ResultCard/
│   │   │   ├── ResultCard.jsx
│   │   │   └── ResultCard.css
│   │   │
│   │   ├── RiskBadge/
│   │   │   ├── RiskBadge.jsx
│   │   │   └── RiskBadge.css
│   │   │
│   │   ├── SeverityBadge/
│   │   │   ├── SeverityBadge.jsx
│   │   │   └── SeverityBadge.css
│   │   │
│   │   ├── StatusIndicator/
│   │   │   ├── StatusIndicator.jsx
│   │   │   └── StatusIndicator.css
│   │   │
│   │   ├── ComponentShowcase.jsx
│   │   └── ComponentShowcase.css
│   │
│   ├── App.jsx
│   ├── index.css
│   └── main.jsx
│
├── index.html
├── package.json
└── package-lock.json
```

---

## Components

### 1. Button

The `Button` component provides reusable buttons for user actions.

#### Example

```jsx
import Button from "./components/Button/Button";

<Button variant="primary">
  Analyze
</Button>
```

#### Purpose

Can be reused for:

* Analyze
* Submit
* Cancel
* Retry
* View Details
* Login
* Other actions

---

### 2. Card

The `Card` component provides a consistent container for displaying content.

#### Example

```jsx
import Card from "./components/Card/Card";

<Card>
  <h2>Security Analysis</h2>
  <p>Analysis information goes here.</p>
</Card>
```

#### Purpose

Can be reused for:

* Dashboard sections
* Analysis information
* Statistics
* History items
* Security information

---

### 3. Input

The `Input` component provides a reusable input field.

#### Example

```jsx
import Input from "./components/Input/Input";

<Input
  label="URL"
  placeholder="Enter URL"
/>
```

#### Purpose

Can be used for:

* URL input
* Search
* Forms
* User information
* Analysis input

---

### 4. Navbar

The `Navbar` component provides the main navigation interface.

#### Purpose

It can be reused across:

* Dashboard
* Analysis
* History
* Settings
* Other application pages

---

### 5. RiskBadge

The `RiskBadge` component displays the security risk level.

#### Supported States

* `SAFE`
* `SUSPICIOUS`
* `MALICIOUS`
* `UNKNOWN`

#### Example

```jsx
import RiskBadge from "./components/RiskBadge/RiskBadge";

<RiskBadge status="SAFE" />
```

Another example:

```jsx
<RiskBadge status="MALICIOUS" />
```

#### Purpose

The same component can be used in:

* Dashboard
* Analysis Result
* History
* Extension UI
* Result Summaries

---

### 6. StatusIndicator

The `StatusIndicator` component provides a clear visual representation of a security status.

#### Supported States

```text
SAFE
SUSPICIOUS
MALICIOUS
UNKNOWN
```

#### Example

```jsx
import StatusIndicator from "./components/StatusIndicator/StatusIndicator";

<StatusIndicator status="SAFE" />
```

---

### 7. SeverityBadge

The `SeverityBadge` component represents the severity of a security issue.

#### Supported Severity Levels

```text
LOW
MEDIUM
HIGH
CRITICAL
```

#### Example

```jsx
import SeverityBadge from "./components/SeverityBadge/SeverityBadge";

<SeverityBadge severity="HIGH" />
```

---

### 8. ResultCard

The `ResultCard` component displays the final security analysis result in a clear format.

It can contain:

* Risk status
* Severity
* Description
* Additional information
* Actions

#### Example

```jsx
import ResultCard from "./components/ResultCard/ResultCard";

<ResultCard
  status="SUSPICIOUS"
  severity="MEDIUM"
/>
```

#### Purpose

The component can be reused wherever an analysis result needs to be displayed.

---

### 9. Alert

The `Alert` component displays important messages to the user.

It can be used for:

* Information
* Warnings
* Success messages
* Errors

#### Example

```jsx
import Alert from "./components/Alert/Alert";

<Alert type="warning">
  This URL requires further analysis.
</Alert>
```

---

### 10. LoadingIndicator

The `LoadingIndicator` component informs the user that an operation is in progress.

#### Example

```jsx
import LoadingIndicator from "./components/LoadingIndicator/LoadingIndicator";

<LoadingIndicator />
```

#### Purpose

Can be used while:

* An analysis is running
* Data is loading
* API requests are processing
* Results are being generated

---

### 11. ErrorMessage

The `ErrorMessage` component displays errors in a consistent format.

#### Example

```jsx
import ErrorMessage from "./components/ErrorMessage/ErrorMessage";

<ErrorMessage message="Unable to complete the analysis." />
```

---

## Security Status System

The Inovix UI uses four main security states.

| Status     | Meaning                                           |
| ---------- | ------------------------------------------------- |
| SAFE       | No significant security threat detected           |
| SUSPICIOUS | Potentially unsafe or unusual activity detected   |
| MALICIOUS  | A known or highly likely security threat detected |
| UNKNOWN    | The system cannot determine the security status   |

These states are designed to make the result understandable at a glance.

---

## Severity System

The UI also supports four severity levels.

| Severity | Meaning                      |
| -------- | ---------------------------- |
| LOW      | Low security impact          |
| MEDIUM   | Moderate security concern    |
| HIGH     | Serious security concern     |
| CRITICAL | Very serious security threat |

---

## Component Reusability

The components are designed to be reused across the application.

For example:

```text
RiskBadge
    │
    ├── Dashboard
    ├── Analysis Result
    ├── History
    └── Extension UI
```

This prevents different pages from creating their own versions of the same UI element.

---

## Component Showcase

A component showcase is included to demonstrate the available UI components.

It can be used by developers to:

* Check how components look
* Test different states
* Understand component usage
* Verify consistency
* Quickly preview the UI foundation

The showcase is available through the frontend application during development.

---

## Technologies

The frontend currently uses:

* React
* Vite
* JavaScript
* CSS
* npm

---

## Requirements

Before running the frontend, install:

* Node.js
* npm

Check the installed versions:

```bash
node --version
npm --version
```

---

## Installation

Navigate to the frontend directory:

```bash
cd frontend
```

Install dependencies:

```bash
npm install
```

---

## Run the Frontend

Start the development server:

```bash
npm run dev
```

Vite will provide a local development URL, normally:

```text
http://localhost:5173
```

Open the URL in a browser to view the application.

---

## Build for Production

To create a production build:

```bash
npm run build
```

To preview the production build locally:

```bash
npm run preview
```

---

## Development Guidelines

When creating new UI components:

1. Keep the component reusable.
2. Keep JSX and component-specific CSS together.
3. Avoid duplicating styles.
4. Use clear and meaningful component names.
5. Keep components focused on one purpose.
6. Support the required security states where applicable.
7. Keep the UI simple and easy to understand.
8. Avoid unnecessary animations.
9. Make components easy for other developers to import and use.

---

## Adding a New Component

A new reusable component should normally follow this structure:

```text
components/
└── ComponentName/
    ├── ComponentName.jsx
    └── ComponentName.css
```

Example:

```text
components/
└── Example/
    ├── Example.jsx
    └── Example.css
```

The component should then be imported wherever it is required.

---

## Current UI States

The following security states are part of the UI foundation:

```text
SAFE
SUSPICIOUS
MALICIOUS
UNKNOWN
```

The following severity states are supported:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

---

## Documentation

Additional UI documentation is available in:

```text
docs/design/
```

Current documentation includes:

```text
docs/design/
├── components.md
├── security-status.md
└── ui-guidelines.md
```

These documents describe:

* Component usage
* Security status meanings
* UI design guidelines
* Reusability rules

---

## Task

This frontend foundation was created as part of:

```text
IQRAH-TASK-001
Inovix UI/UX & Reusable Component System
```

The objective of this task is to establish a reusable and consistent visual foundation for the Inovix application.

---

## Scope

### Included

* UI/UX foundation
* Reusable components
* Security status indicators
* Risk indicators
* Severity indicators
* Loading states
* Error states
* Result display
* Navigation
* Component showcase
* UI documentation

### Not Included

The following are outside the scope of this task:

* Backend development
* Machine learning implementation
* Security engine implementation
* Browser extension development
* Application business logic
* API integration

These features can use the reusable components provided by this frontend foundation.

---

## For Other Developers

Developers working on application logic can import and reuse these components instead of creating new UI elements.

For example:

```jsx
import RiskBadge from "./components/RiskBadge/RiskBadge";
import ResultCard from "./components/ResultCard/ResultCard";

function AnalysisResult() {
  return (
    <>
      <RiskBadge status="SAFE" />

      <ResultCard
        status="SAFE"
        severity="LOW"
      />
    </>
  );
}

export default AnalysisResult;
```

This keeps the Inovix interface consistent throughout the application.

---

## Branch

The UI/UX work is developed on:

```text
iqrah/frontend-foundation
```

---

## Contribution

Before making frontend changes:

```bash
git pull origin main
```

Create a feature branch:

```bash
git checkout -b feature/your-feature-name
```

After completing the changes:

```bash
git add .
```

Commit the changes:

```bash
git commit -m "feat: describe your frontend change"
```

Push the feature branch:

```bash
git push -u origin feature/your-feature-name
```

Then create a Pull Request against the `main` branch.

---

## Status

| Area                       | Status    |
| -------------------------- | --------- |
| Frontend UI/UX foundation  | Completed |
| Reusable component system  | Completed |
| Security status indicators | Completed |
| Risk indicators            | Completed |
| Severity indicators        | Completed |
| Loading states             | Completed |
| Error states               | Completed |
| Result cards               | Completed |
| Navigation                 | Completed |
| Component showcase         | Completed |
| UI documentation           | Completed |

---

## Important

Do not commit `node_modules` to the repository.

The following should be ignored by Git:

```text
node_modules/
```

Dependencies can always be installed again using:

```bash
npm install
```

The required dependency information is maintained through:

```text
package.json
package-lock.json
```

---

## License

This project is developed as part of the Inovix project and is intended for project development and educational purposes.
