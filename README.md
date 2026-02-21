<p align="center">
  <img src="./img.png" alt="Project Banner" width="100%">
</p>

# QuickConnect

## It is a platform which connects skilled workers in need of employment (plumbers, electricians etc), with clients who require their services.

### Team Name: [Seeta&Geeta]

### Team Members
- Member 1: [Nandita M Menon] - [Mar Baselios College of Engineering and Technology]
- Member 2: [Anasooya P Nair] - [Mar Baselios College of Engineering and Technology]

### Hosted Project Link
nil

### Project Description
It is a platform which connects skilled workers in need of employment (plumbers, electricians etc), with clients who require their services. It allowes workers to sign up after adding their skillset, and their identities are verified via Aadhar verification. Clients enter their requirements in their region and the ppair are matched together. 
### The Problem statement
Most workers rely on word of mouth for employment opportunities, which often leads to periods of unemployment. Conversely, there are people who have need for skilled labour, but do not know how or where to find it. 
### The Solution
This platform connects people with their requirements. It is easy to use with minimal complexity. 
**---

## Technical Details

### Technologies/Components Used

**For Software:**
- Languages used: Python, HTML, CSS
- Frameworks used:- 
- Libraries used: flask` - web framework, `werkzeug` - comes with Flask, used for password hashing, `sqlite3` - built into Python, no install needed, `random` - built into Python, `datetime` - built into Python, `functools
- Tools used: VS Code, Google Sheets

**For Hardware:**
- Main components: [List main components]
- Specifications: [Technical specifications]
- Tools required: [List tools needed]

---

## Features

List the key features of your project:
- Feature 1: [Authentication - Login, verification of identinty]
- Feature 2: [Client Side - hire worker, Start/Stop OTP]
- Feature 3: [Worker Side -Assigned jobs, rating, Submit ENd OTP]
- Feature 4: [Job Flow]
- Feature 5: [SOS System]

---

## Implementation

### For Software:

#### Installation
```bash
[pip install flask]
```

#### Run
```bash
[py app.py]
```

### For Hardware:

#### Components Required
NA

#### Circuit Setup
NA

---

## Project Documentation

### For Software:

#### Screenshots (Add at least 3)

![Screenshot1] <img width="1360" height="392" alt="image" src="https://github.com/user-attachments/assets/a994da90-19f4-480e-9667-3c418094ec35" />

Basic HTML view of login screen 
![Screenshot2] <img width="1135" height="489" alt="image" src="https://github.com/user-attachments/assets/161406c2-4c02-423d-aea5-01c12acd5577" />

Basic HTML view of Registration Screen
![Screenshot3] <img width="603" height="508" alt="image" src="https://github.com/user-attachments/assets/fa5405f0-13a8-4cb4-8eec-00181b255f46" />

Basic HTML view of matching of worker to client
#### Diagrams

**System Architecture:**

![Architecture Diagram](docs/architecture.png)
<img width="660" height="262" alt="image" src="https://github.com/user-attachments/assets/fdea3696-67b5-4006-843d-bf768aa48796" />


**Application Workflow:**

![Workflow](docs/workflow.png)
*Add caption explaining your workflow*

---

### For Hardware:

#### Schematic & Circuit
NA

#### Build Photos

NA

---

## Additional Documentation

### For Web Projects with Backend:

#### API Documentation

**Base URL:** `https://api.yourproject.com`

##### Endpoints

**GET /api/endpoint**
- **Description:** [What it does]
- **Parameters:**
  - `param1` (string): [Description]
  - `param2` (integer): [Description]
- **Response:**
```json
{
  "status": "success",
  "data": {}
}
```

**POST /api/endpoint**
- **Description:** [What it does]
- **Request Body:**
```json
{
  "field1": "value1",
  "field2": "value2"
}
```
- **Response:**
```json
{
  "status": "success",
  "message": "Operation completed"
}
```

[Add more endpoints as needed...]

---

### For Mobile Apps:

#### App Flow Diagram

![App Flow](docs/app-flow.png)
*Explain the user flow through your application*

#### Installation Guide

**For Android (APK):**
1. Download the APK from [Release Link]
2. Enable "Install from Unknown Sources" in your device settings:
   - Go to Settings > Security
   - Enable "Unknown Sources"
3. Open the downloaded APK file
4. Follow the installation prompts
5. Open the app and enjoy!

**For iOS (IPA) - TestFlight:**
1. Download TestFlight from the App Store
2. Open this TestFlight link: [Your TestFlight Link]
3. Click "Install" or "Accept"
4. Wait for the app to install
5. Open the app from your home screen

**Building from Source:**
```bash
# For Android
flutter build apk
# or
./gradlew assembleDebug

# For iOS
flutter build ios
# or
xcodebuild -workspace App.xcworkspace -scheme App -configuration Debug
```

---

### For Hardware Projects:

#### Bill of Materials (BOM)

| Component | Quantity | Specifications | Price | Link/Source |
|-----------|----------|----------------|-------|-------------|
| Arduino Uno | 1 | ATmega328P, 16MHz | ₹450 | [Link] |
| LED | 5 | Red, 5mm, 20mA | ₹5 each | [Link] |
| Resistor | 5 | 220Ω, 1/4W | ₹1 each | [Link] |
| Breadboard | 1 | 830 points | ₹100 | [Link] |
| Jumper Wires | 20 | Male-to-Male | ₹50 | [Link] |
| [Add more...] | | | | |

**Total Estimated Cost:** ₹[Amount]

#### Assembly Instructions

**Step 1: Prepare Components**
1. Gather all components listed in the BOM
2. Check component specifications
3. Prepare your workspace
![Step 1](images/assembly-step1.jpg)
*Caption: All components laid out*

**Step 2: Build the Power Supply**
1. Connect the power rails on the breadboard
2. Connect Arduino 5V to breadboard positive rail
3. Connect Arduino GND to breadboard negative rail
![Step 2](images/assembly-step2.jpg)
*Caption: Power connections completed*

**Step 3: Add Components**
1. Place LEDs on breadboard
2. Connect resistors in series with LEDs
3. Connect LED cathodes to GND
4. Connect LED anodes to Arduino digital pins (2-6)
![Step 3](images/assembly-step3.jpg)
*Caption: LED circuit assembled*

**Step 4: [Continue for all steps...]**

**Final Assembly:**
![Final Build](images/final-build.jpg)
*Caption: Completed project ready for testing*

---

### For Scripts/CLI Tools:

#### Command Reference

**Basic Usage:**
```bash
python script.py [options] [arguments]
```

**Available Commands:**
- `command1 [args]` - Description of what command1 does
- `command2 [args]` - Description of what command2 does
- `command3 [args]` - Description of what command3 does

**Options:**
- `-h, --help` - Show help message and exit
- `-v, --verbose` - Enable verbose output
- `-o, --output FILE` - Specify output file path
- `-c, --config FILE` - Specify configuration file
- `--version` - Show version information

**Examples:**

```bash
# Example 1: Basic usage
python script.py input.txt

# Example 2: With verbose output
python script.py -v input.txt

# Example 3: Specify output file
python script.py -o output.txt input.txt

# Example 4: Using configuration
python script.py -c config.json --verbose input.txt
```

#### Demo Output

**Example 1: Basic Processing**

**Input:**
```
This is a sample input file
with multiple lines of text
for demonstration purposes
```

**Command:**
```bash
python script.py sample.txt
```

**Output:**
```
Processing: sample.txt
Lines processed: 3
Characters counted: 86
Status: Success
Output saved to: output.txt
```

**Example 2: Advanced Usage**

**Input:**
```json
{
  "name": "test",
  "value": 123
}
```

**Command:**
```bash
python script.py -v --format json data.json
```

**Output:**
```
[VERBOSE] Loading configuration...
[VERBOSE] Parsing JSON input...
[VERBOSE] Processing data...
{
  "status": "success",
  "processed": true,
  "result": {
    "name": "test",
    "value": 123,
    "timestamp": "2024-02-07T10:30:00"
  }
}
[VERBOSE] Operation completed in 0.23s
```

---

## Project Demo

### Video
[Add your demo video link here - YouTube, Google Drive, etc.]

*Explain what the video demonstrates - key features, user flow, technical highlights*

### Additional Demos
[Add any extra demo materials/links - Live site, APK download, online demo, etc.]

---

## AI Tools Used (Optional - For Transparency Bonus)

Claude - debugging
ChatGPT - front end nd elements of back end
Gemini - Integration
**Tool Used:** [e.g., GitHub Copilot, v0.dev, Cursor, ChatGPT, Claude]

**Purpose:** [What you used it for]
- Example: "Generated boilerplate React components"
- Example: "Debugging assistance for async functions"
- Example: "Code review and optimization suggestions"

**Key Prompts Used:**
- "Create a REST API endpoint for user authentication"
- "Debug this async function that's causing race conditions"
- "Optimize this database query for better performance"

**Percentage of AI-generated code:** [Approximately X%]

**Human Contributions:**
- Architecture design and planning
- Custom business logic implementation
- Integration and testing
- UI/UX design decisions

*Note: Proper documentation of AI usage demonstrates transparency and earns bonus points in evaluation!*

---

## Team Contributions

- [Name 1]: [Specific contributions - e.g., Frontend development, API integration, etc.]
- [Name 2]: [Specific contributions - e.g., Backend development, Database design, etc.]
- [Name 3]: [Specific contributions - e.g., UI/UX design, Testing, Documentation, etc.]

---

## License
NA

**Common License Options:**
- MIT License (Permissive, widely used)
- Apache 2.0 (Permissive with patent grant)
- GPL v3 (Copyleft, requires derivative works to be open source)

---

Made with ❤️ at TinkerHub
