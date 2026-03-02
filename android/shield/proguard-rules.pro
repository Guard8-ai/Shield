# Shield Android SDK ProGuard Rules

# Keep all public Shield APIs
-keep class ai.dikestra.shield.** { *; }
-keepclassmembers class ai.dikestra.shield.** { *; }

# Keep crypto classes
-keep class javax.crypto.** { *; }
-keep class java.security.** { *; }

# Don't warn about missing annotations
-dontwarn javax.annotation.**
