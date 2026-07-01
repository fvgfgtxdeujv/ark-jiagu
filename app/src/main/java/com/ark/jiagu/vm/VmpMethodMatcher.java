package com.ark.jiagu.vm;

import java.util.*;

class VmpMethodMatcher {

    static class MethodRule {
        String raw;
        String packageName;
        String className;
        String methodName;
    }

    static List<MethodRule> parseMethodRules(String... methodRules) {
        List<MethodRule> rules = new ArrayList<>();

        if (methodRules == null) {
            return rules;
        }

        for (String ruleText : methodRules) {
            if (ruleText == null) {
                continue;
            }

            ruleText = ruleText.trim();
            if (ruleText.isEmpty()) {
                continue;
            }

            String[] parts = ruleText.split("\\.");
            if (parts.length < 3) {
                System.out.println("跳过非法规则：" + ruleText);
                continue;
            }

            String methodName = parts[parts.length - 1];
            String className = parts[parts.length - 2];

            StringBuilder pkg = new StringBuilder();
            for (int i = 0; i < parts.length - 2; i++) {
                if (i > 0) {
                    pkg.append(".");
                }
                pkg.append(parts[i]);
            }

            MethodRule rule = new MethodRule();
            rule.raw = ruleText;
            rule.packageName = pkg.toString();
            rule.className = className;
            rule.methodName = methodName;

            rules.add(rule);

            System.out.println("添加抽取规则：" + rule.raw
                    + " 鍖呭悕=" + rule.packageName
                    + " 类名=" + rule.className
                    + " 方法=" + rule.methodName);
        }

        return rules;
    }

    static boolean matchAnyRule(List<MethodRule> rules, String javaClassName, String methodName) {
        for (MethodRule rule : rules) {
            if (matchRule(rule, javaClassName, methodName)) {
                return true;
            }
        }
        return false;
    }

    static boolean matchRule(MethodRule rule, String javaClassName, String methodName) {
        if (rule == null || javaClassName == null || methodName == null) {
            return false;
        }

        int lastDot = javaClassName.lastIndexOf('.');
        String pkg = lastDot >= 0 ? javaClassName.substring(0, lastDot) : "";
        String cls = lastDot >= 0 ? javaClassName.substring(lastDot + 1) : javaClassName;

        return matchPart(rule.packageName, pkg)
                && matchPart(rule.className, cls)
                && matchPart(rule.methodName, methodName);
    }

    static boolean matchPart(String rulePart, String value) {
        if ("*".equals(rulePart)) {
            return true;
        }
        return rulePart.equals(value);
    }
}
