# identity-serializer-fory

This is an extension that can be used to improve the DB performance by leveraging [Apache Fory](https://fory.apache.org/) serialization instead of the default Java serializer.

[![Stackoverflow](https://img.shields.io/badge/Ask%20for%20help%20on-Stackoverflow-orange)](https://stackoverflow.com/questions/tagged/wso2is)
[![Discord](https://img.shields.io/badge/Join%20us%20on-Discord-%23e01563.svg)](https://discord.gg/wso2)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/wso2/product-is/blob/master/LICENSE)
[![Twitter](https://img.shields.io/twitter/follow/wso2.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=wso2)

## Building from the Source

1. Install Java SE Development Kit 11 or later.
2. Install Apache Maven 3.x.x (https://maven.apache.org/download.cgi).
3. Get a clone or download the source from this repository (https://github.com/wso2-extensions/identity-serializer-fory).
4. Run the Maven command `mvn clean install` from the identity-serializer-fory directory.
5. Once the build completes, navigate to identity-serializer-fory/org.wso2.carbon.identity.serializer.fory/target to view the jar.

## Instructions to Integrate the Extension with WSO2 Identity Server

### Step 1: Obtaining and adding the extension to WSO2 Identity Server
1. Download the latest released version of the jar from https://github.com/wso2-extensions/identity-serializer-fory/releases.
2. Alternatively, the jar can be built from the source as described above in [Building from the Source](#building-from-the-source).
3. Add the jar file to \<IS-HOME\>/repository/components/dropins.

### Step 2: Adding the Apache Fory library
1. Download [fory-core 1.6.0](https://repo1.maven.org/maven2/org/apache/fory/fory-core/1.6.0/fory-core-1.6.0.jar).
2. Place it in \<IS-HOME\>/lib. This is the only jar needed, as Fory bundles its compiler internally.

Fory builds a dedicated serializer class for each type of session object at runtime, and that
generated class has to be loaded together with the class it serializes. Those classes belong to
several different Identity Server components, so Fory needs to be reachable from all of them. The
common lib folder provides that; placing it inside the extension jar would make it visible only to
this extension.

### Step 3: Updating the launch.ini file
1. Add the following set of lines in between `com.sun.tools.internal.ws.spi` and `org.wso2.carbon.bootstrap`
   in \<IS-HOME\>/repository/conf/etc/launch.ini.

  ```
  sun.misc,\
  org.apache.fory.*,\
  ```

Both entries are required:

- `sun.misc` — Fory uses `sun.misc.Unsafe` internally, and OSGi does not expose JDK-internal
  packages by default.
- `org.apache.fory.*` — makes the library added in Step 2 reachable from every component. Without
  this entry, Step 2 alone has no effect.

### Step 4: (Optional) Configuring the Compatibility Mode
By default, the serializer runs in `CompatibleMode.COMPATIBLE`, which tolerates class shape changes
(fields added or removed) between the time a session is written and the time it is read back. This
is required because sessions are persisted long-term in the DB across product upgrades.

Compatibility mode can be turned off to fall back to `CompatibleMode.SCHEMA_CONSISTENT`, which does
not write per-class field-name schema on the wire and is therefore faster and smaller — but any
class shape change between write and read will invalidate existing rows. To do so, add the following
to \<IS-HOME\>/repository/conf/deployment.toml and restart the server:

   ```toml
   [fory]
   enable_compatibility_mode = false
   ```

If `fory.enable_compatibility_mode` is not set, compatibility mode defaults to `true`.
