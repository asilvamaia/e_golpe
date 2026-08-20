allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

val newBuildDir: Directory =
    rootProject.layout.buildDirectory
        .dir("../../build")
        .get()
rootProject.layout.buildDirectory.value(newBuildDir)

subprojects {
    val newSubprojectBuildDir: Directory = newBuildDir.dir(project.name)
    project.layout.buildDirectory.value(newSubprojectBuildDir)
}
subprojects {
    project.evaluationDependsOn(":app")
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}

subprojects {
    val subproject = this
    val configureProject = {
        if (subproject.hasProperty("android")) {
            val androidExt = subproject.extensions.getByName("android")
            try {
                val method = androidExt.javaClass.getMethod("compileSdkVersion", Int::class.javaPrimitiveType)
                method.invoke(androidExt, 36)
            } catch (e: Exception) {
                try {
                    val method = androidExt.javaClass.getMethod("compileSdkVersion", String::class.java)
                    method.invoke(androidExt, "android-36")
                } catch (ex: Exception) {
                    // Ignore
                }
            }
        }
    }

    if (subproject.state.executed) {
        configureProject()
    } else {
        subproject.afterEvaluate {
            configureProject()
        }
    }
}
