# JNI constructs this private wire carrier by its binary class name and exact
# constructor descriptor.
-keep class org.xrayrust.mobile.NativeTunDiagnosticEvent {
    <init>(int, int, java.lang.String, java.lang.String, java.lang.String, long[]);
}

# Keep the Java names of methods whose symbols are resolved through JNI.
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# Called by native TUN admission workers after asynchronous flow creation.
-keep class org.xrayrust.mobile.NativeTunAdmission {
    boolean admitNative(long, int, byte[], int, byte[], int);
}
