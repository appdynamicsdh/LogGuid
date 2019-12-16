package com.appdynamics;

import com.appdynamics.instrumentation.sdk.Rule;
import com.appdynamics.instrumentation.sdk.SDKClassMatchType;
import com.appdynamics.instrumentation.sdk.SDKStringMatchType;
import com.appdynamics.instrumentation.sdk.template.AGenericInterceptor;
import com.singularity.ee.agent.appagent.kernel.AgentProperties;
import com.singularity.ee.agent.appagent.services.logmonitoring.guidmonitor.LogGuidInjectionConstants;
import com.singularity.ee.agent.appagent.services.logmonitoring.guidmonitor.LogGuidInjectionReflector;
import com.singularity.ee.agent.appagent.services.logmonitoring.guidmonitor.LogGuidInjector;


import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * created by haojun.li on 7/10/18
 */
public class ParentGUIDInjector extends AGenericInterceptor {

    public static final int LOG4J_CACHE_INDEX = 0;
    public static final int SLF4J_CACHE_INDEX = 1;

    public static final String DEFAULT_FORMAT_STRING = "AD_PARENT_REQUEST_GUID[" + (AgentProperties.getInstance().isDotNet() ? "{0}]" : "%s]");

    /*
     * Log4J MDC
     */
    private static final String LOG4J_MDC_CLASS_NAME = "org.apache.log4j.MDC";
    private static final String LOG4J_MDC_PUT_METHOD_NAME = LogGuidInjectionConstants.PUT_METHOD_NAME;
    private static final Class[] LOG4J_MDC_PUT_METHOD_ARG_TYPES = new Class[]{String.class, Object.class};
    private static final String LOG4J_MDC_REMOVE_METHOD_NAME = LogGuidInjectionConstants.REMOVE_METHOD_NAME;
    private static final Class[] LOG4J_MDC_REMOVE_METHOD_ARG_TYPES = new Class[]{String.class};

    /**
     * Slf4j MDC
     */
    private static final String SLF4J_MDC_CLASS_NAME = "org.slf4j.MDC";
    private static final String SLF4J_MDC_PUT_METHOD_NAME = LogGuidInjectionConstants.PUT_METHOD_NAME;
    private static final Class[] SLF4J_MDC_PUT_METHOD_ARG_TYPES = new Class[]{String.class, String.class};
    private static final String SLF4J_MDC_REMOVE_METHOD_NAME = LogGuidInjectionConstants.REMOVE_METHOD_NAME;
    private static final Class[] SLF4J_MDC_REMOVE_METHOD_ARG_TYPES = new Class[]{String.class};

    public final LogGuidInjector log4jInjector =
            new LogGuidInjector(
                    "AD.parentRequestGUID",
                    LOG4J_MDC_CLASS_NAME,
                    LOG4J_MDC_PUT_METHOD_NAME,
                    LOG4J_MDC_PUT_METHOD_ARG_TYPES,
                    LOG4J_MDC_REMOVE_METHOD_NAME,
                    LOG4J_MDC_REMOVE_METHOD_ARG_TYPES,
                    LOG4J_CACHE_INDEX);

    public final LogGuidInjector slf4jInjector =
            new LogGuidInjector(
                    "AD.parentRequestGUID",
                    SLF4J_MDC_CLASS_NAME,
                    SLF4J_MDC_PUT_METHOD_NAME,
                    SLF4J_MDC_PUT_METHOD_ARG_TYPES,
                    SLF4J_MDC_REMOVE_METHOD_NAME,
                    SLF4J_MDC_REMOVE_METHOD_ARG_TYPES,
                    SLF4J_CACHE_INDEX);

    // These fields record the number of times we have failed to tag a particular framework
    private final AtomicInteger log4jFailCount = new AtomicInteger(0);
    private final AtomicInteger slf4jFailCount = new AtomicInteger(0);

    // These flags indicate if we have decided to give up on a particular framework
    private boolean skipLog4j = false;
    private boolean skipSlf4j = false;
    ;
    public ParentGUIDInjector() {
        super();
    }

    @Override
    public Object onMethodBegin(Object o, String s, String s1, Object[] objects) {

        try {
            String parentGuid = com.singularity.ee.agent.appagent.services.transactionmonitor.TransactionMonitoringService.getTransactionMonitor().getBTContext().getParentTranGUID();

            if("".equals(parentGuid) || parentGuid==null){
                return null;
            }

            onStart(parentGuid);
            return parentGuid;

        }catch(Exception e){
            getLogger().info("Exception",e);
        }

        return null;

    }

    @Override
    public void onMethodEnd(Object o, Object o1, String s, String s1, Object[] objects, Throwable throwable, Object o2) {
        if("".equals(o) || o==null){
        }else {
            onEnd();
        }
    }

    @Override
    public List<Rule> initializeRules() {
        List<Rule> result = new ArrayList<>();


        Rule.Builder springWeb = new Rule.Builder("org.springframework.web.servlet.DispatcherServlet");
        springWeb = springWeb.classMatchType(SDKClassMatchType.MATCHES_CLASS).classStringMatchType(SDKStringMatchType.EQUALS);
        springWeb = springWeb.methodMatchString("doService").methodStringMatchType(SDKStringMatchType.EQUALS);

        Rule.Builder glassfish = new Rule.Builder("org.glassfish.jersey.server.model.internal.AbstractJavaResourceMethodDispatcher");
        glassfish = glassfish.classMatchType(SDKClassMatchType.INHERITS_FROM_CLASS).classStringMatchType(SDKStringMatchType.EQUALS);
        glassfish = glassfish.methodMatchString("invoke").methodStringMatchType(SDKStringMatchType.EQUALS);

        Rule.Builder glassfish2 = new Rule.Builder("org.glassfish.jersey.server.model.ResourceMethodInvoker");
        glassfish2 = glassfish2.classMatchType(SDKClassMatchType.MATCHES_CLASS).classStringMatchType(SDKStringMatchType.EQUALS);
        glassfish2 = glassfish2.methodMatchString("invoke").methodStringMatchType(SDKStringMatchType.EQUALS);

        Rule.Builder glassfish3 = new Rule.Builder("org.glassfish.jersey.server.model.ResourceMethodInvoker");
        glassfish3 = glassfish3.classMatchType(SDKClassMatchType.MATCHES_CLASS).classStringMatchType(SDKStringMatchType.EQUALS);
        glassfish3 = glassfish3.methodMatchString("apply").methodStringMatchType(SDKStringMatchType.EQUALS);

        Rule.Builder glassfish4 = new Rule.Builder("org.glassfish.jersey.server.ServerRuntime");
        glassfish4 = glassfish4.classMatchType(SDKClassMatchType.MATCHES_CLASS).classStringMatchType(SDKStringMatchType.EQUALS);
        glassfish4 = glassfish4.methodMatchString("process").methodStringMatchType(SDKStringMatchType.EQUALS);


        /*org.glassfish.jersey.server.model.ResourceMethodInvoker.invoke(ResourceMethodInvoker.java:389)

        ! at org.glassfish.jersey.server.model.ResourceMethodInvoker.apply(ResourceMethodInvoker.java:347)*/



        result.add(glassfish.build());
        result.add(springWeb.build());
        result.add(glassfish3.build());
        result.add(glassfish2.build());
        result.add(glassfish4.build());

        try {
            if(System.getProperties().containsKey("appdynamics.entrypoints.file")) {
                String propertiesFile = System.getProperties().get("appdynamics.entrypoints.file").toString();
                if (!("".equals(propertiesFile) || propertiesFile == null)) {

                    try (BufferedReader reader = new BufferedReader(new FileReader(propertiesFile))) {
                        while (true) {

                            //org.springframework.web.servlet.DispatcherServlet,MATCHES_CLASS,EQUALS,doService,EQUALS

                            String line = reader.readLine();

                            if (line == null) {
                                break;
                            }
                            String[] split = line.split(",");

                            String className = split[0];
                            String classMatch = split[1];
                            String classMatchString = split[2];
                            String methodName = split[3];
                            String methodMatch = split[4];

                            SDKClassMatchType classMatchType = SDKClassMatchType.valueOf(classMatch);
                            SDKStringMatchType classMatchStringType = SDKStringMatchType.valueOf(classMatchString);

                            SDKStringMatchType methodMatchType = SDKStringMatchType.valueOf(methodMatch);

                            Rule.Builder rule = new Rule.Builder(className);
                            rule = rule.classMatchType(classMatchType).classStringMatchType(classMatchStringType);
                            rule = rule.methodMatchString(methodName).methodStringMatchType(methodMatchType);
                            result.add(rule.build());


                        }
                    }



                }
            }

        }catch(Exception e){
        }


        return result;
    }

    public void onStart(String guid) {

        // Try to inject a guid into the log4j MDC, if we haven't exceeded the max number of failures yet
        if (!skipLog4j) {
            boolean result = LogGuidInjectionReflector.safeTag(log4jInjector,
                    String.format(DEFAULT_FORMAT_STRING, guid));
            if (!result) {
                if (log4jFailCount.incrementAndGet() > LogGuidInjectionConstants.MAX_FRAMEWORK_FAIL_COUNT) {
                    getLogger().info(
                            "No longer attempting to inject BT guid for log4j after " + log4jFailCount + " failures.");
                    skipLog4j = true;
                }
            }
        }

        // Try to inject a guid into the slf4j MDC, if we haven't exceeded the max number of failures yet
        if (!skipSlf4j) {
            boolean result = LogGuidInjectionReflector.safeTag(slf4jInjector,
                    String.format(DEFAULT_FORMAT_STRING, guid));
            if (!result) {
                if (slf4jFailCount.incrementAndGet() > LogGuidInjectionConstants.MAX_FRAMEWORK_FAIL_COUNT) {
                    getLogger().info(
                            "No longer attempting to inject BT guid for slf4j after " + slf4jFailCount + " failures.");
                    skipSlf4j = true;
                }
            }
        }
    }

    public void onEnd() {
        if (!skipLog4j) {
            LogGuidInjectionReflector.safeUnTag(log4jInjector);
        }
        if (!skipSlf4j) {
            LogGuidInjectionReflector.safeUnTag(slf4jInjector);
        }
    }

    public void reset() {
        log4jFailCount.set(0);
        slf4jFailCount.set(0);
        skipLog4j = false;
        skipSlf4j = false;
    }

}