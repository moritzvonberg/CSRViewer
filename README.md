## CSR Viewer application (WIP)

### Prerequisites
Gradle and Java 17+ are installed on your system.

### How to get the source code.
1. Navigate to a directory you want to use.
2. Clone the repository: `git clone --depth=1 https://github.com/moritzvonberg/CSRViewer.git`

### How to build/run the application
1. Navigate to the cloned repository (`cd CSRViewer` if you're continuing from the previous section).
2. Launch the server with `gradle bootRun`
3. Navigate to `127.0.0.1`

### How to create the fat JAR
1. In the repository root, execute the command `gradle bootJar`
2. The fat JAR should now be created in `<repository root>/build/libs/csrviewer-fat.jar`
3. You can now run the server from the JAR file with the command `java -jar <path to fat jar>`