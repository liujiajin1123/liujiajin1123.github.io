---
title: tomcat源码分析（一）
tags:
  - tomcat源码分析
  - 模板方法设计模式
  - 监听器设计模式
  - 类加载器
  - 设计模式
id: '83'
categories:
  - - tomcat
date: 2025-04-13 17:51:59
---

在web开发过程中，Tomcat是一款使用率极高的中间件，作为Apache顶级项目之一，它集成了多种精巧的设计模式。学习其优秀的代码实践，能有效提升自身代码质量。本文将结合Server和Service的启动过程，拆解类加载器的双亲委派机制，以及监听器、模板方法两种核心设计模式，和大家一起交流学习。

## 实验准备与步骤

Tomcat默认使用Ant进行构建，为了方便源码分析，我们改用Maven管理依赖。实验环境及步骤如下：

1. JDK版本：openjdk 11

2. 拉取源码：使用git克隆Tomcat 7源码仓库

```bash
git clone https://gitee.com/jiajinliu/tomcat70.git
```

1. 导入IDE：将源码导入Eclipse

2. 调试入口：找到 `org.apache.catalina.startup.Bootstrap` 类，在main方法设置断点，启动Tomcat进入调试模式，跟踪启动流程。

## 类加载器的使用与原理

Tomcat启动过程中，Catalina对象扮演着核心角色——负责加载service.xml配置文件、启动Service组件。以下是Catalina对象的创建核心代码：

```java
Class startupClass = catalinaLoader.loadClass("org.apache.catalina.startup.Catalina");
Object startupInstance = startupClass.newInstance();
// Set the shared extensions class loader
if (log.isDebugEnabled())
    log.debug("Setting startup class properties");
String methodName = "setParentClassLoader";
Class paramTypes[] = new Class[1];
paramTypes[0] = Class.forName("java.lang.ClassLoader");
Object paramValues[] = new Object[1];
paramValues[0] = sharedLoader;
Method method = startupInstance.getClass().getMethod(methodName, paramTypes);
method.invoke(startupInstance, paramValues);
catalinaDaemon = startupInstance;
```

### 为什么用类加载器实例化Catalina？

核心目的是**避免类冲突**。在实际开发中，我们可能需要在同一个JVM中加载同一个类的不同版本，而默认的类加载机制无法实现这一点，通过自定义类加载器可以解决该问题。

举个简单示例理解原理：

假设有两个版本的MyClass类，分别位于不同JAR包中：

- mylib-1.0.jar：包含MyClass 1.0版本

- mylib-2.0.jar：包含MyClass 2.0版本

两个版本的核心代码如下：

```java
// MyClass 版本 1.0（位于 mylib-1.0.jar）
public class MyClass {
    public void printVersion() {
        System.out.println("MyClass version 1.0");
    }
}

// MyClass 版本 2.0（位于 mylib-2.0.jar）
public class MyClass {
    public void printVersion() {
        System.out.println("MyClass version 2.0");
    }
}
```

若使用同一个类加载器加载两个版本，会出现类冲突，无法正常使用。通过自定义类加载器，可实现两个版本的独立加载，示例代码如下：

```java
import java.net.URL;
import java.net.URLClassLoader;

public class Main {
    public static void main(String[] args) throws Exception {
        // 创建自定义类加载器，指定两个版本的JAR路径
        URL[] urls = {
            new URL("file:/path/to/mylib-1.0.jar"),
            new URL("file:/path/to/mylib-2.0.jar")
        };
        CustomClassLoader classLoader = new CustomClassLoader(urls);
        
        // 加载两个版本的MyClass（实际需通过不同类加载器实现，此处简化演示）
        Class myClass1 = classLoader.loadClass("com.example.mylib.MyClass");
        Class myClass2 = classLoader.loadClass("com.example.mylib.MyClass");
        
        // 实例化并调用方法
        Object instance1 = myClass1.getDeclaredConstructor().newInstance();
        Object instance2 = myClass2.getDeclaredConstructor().newInstance();
        myClass1.getMethod("printVersion").invoke(instance1);
        myClass2.getMethod("printVersion").invoke(instance2);
        
        // 演示类冲突（同一类加载器下，两个Class对象本质是同一个，会出现异常）
        System.out.println("instance1 instanceof MyClass: " + (instance1 instanceof com.example.mylib.MyClass));
        System.out.println("instance2 instanceof MyClass: " + (instance2 instanceof com.example.mylib.MyClass));
    }
}
```

完整示例代码可参考仓库：[https://gitee.com/jiajinliu/analysis_web_server.git](https://gitee.com/jiajinliu/analysis_web_server.git)

## Server 启动过程（设计模式应用）

Tomcat的Server启动过程，巧妙运用了两种设计模式，实现了代码的解耦和扩展灵活性。

### 1. 监听器设计模式（观察者模式）

Server接口的实现类是`StandardService`，该类通过`Lifecycle`接口和`LifecycleListener`接口，实现了观察者模式。

核心逻辑：StandardService在自身状态发生变化（如启动、停止）时，会自动通知所有注册的监听器，从而实现灵活的事件处理，降低组件间的耦合度。

![tomcat监听器](/wp-content/uploads/2025/04/tomcat监听器.jpg){.alignnone}

### 2. 模板方法设计模式

抽象类`LifecycleBase`实现了`Lifecycle`接口的start方法，定义了Server启动的固定流程（模板），确保启动顺序的一致性。

核心逻辑：启动流程由一系列固定方法组成，其中`startInternal`方法为抽象方法，需要由子类（如StandardService）实现。子类可通过重写抽象方法扩展自身逻辑，无需修改父类的模板方法，符合“开闭原则”。

![tomcat_模板方法](/wp-content/uploads/2025/04/tomcat_模板方法.jpg){.alignnone}

## Service 启动过程

Service的核心职责是分别启动Connector（连接器）和Engine（引擎）。为了保证多线程环境下的启动安全，Tomcat使用`synchronized`加锁处理，确保Container和Connector的启动过程有序、安全执行。

核心源码如下：

```java
@Override
protected void startInternal() throws LifecycleException {
    if(log.isInfoEnabled())
        log.info(sm.getString("standardService.start.name", this.name));
    setState(LifecycleState.STARTING);

    // 先启动定义的Container
    if (container != null) {
        synchronized (container) {
            container.start();
        }
    }

    // 启动所有Executor
    synchronized (executors) {
        for (Executor executor: executors) {
            executor.start();
        }
    }

    // 再启动定义的Connectors
    synchronized (connectorsLock) {
        for (Connector connector: connectors) {
            try {
                // 若已失败，不再尝试启动
                if (connector.getState() != LifecycleState.FAILED) {
                    connector.start();
                }
            } catch (Exception e) {
                log.error(sm.getString(
                    "standardService.connector.startFailed", connector), e);
            }
        }
    }
}
```

## 实验总结

通过跟踪Tomcat中Server和Service的启动流程，我们重点掌握了以下核心知识点：

- 类加载器的核心作用：解决类冲突，实现同一JVM中加载同一类的不同版本；

- 两种设计模式的应用：监听器模式实现事件解耦，模板方法模式定义固定流程并支持扩展；

- 多线程安全：通过synchronized锁，保证Service启动过程中多线程环境下的正确性。

后续将继续分析Tomcat源码中的其他核心组件，欢迎持续关注~
