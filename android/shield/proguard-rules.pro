# Shield Android SDK ProGuard Rules

# Keep all public Shield APIs
-keep class ai.guard8.shield.** { *; }
-keepclassmembers class ai.guard8.shield.** { *; }

# Keep crypto classes
-keep class javax.crypto.** { *; }
-keep class java.security.** { *; }

# Don't warn about missing annotations
-dontwarn javax.annotation.**
