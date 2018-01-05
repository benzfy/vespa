// Copyright 2018 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.hosted.node.admin.task;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Pattern;

public class AddYumRepoTask implements Task {
    private static final Pattern REPOSITORY_ID_PATTERN = Pattern.compile("^[a-zA-Z_-]+$");

    private final Params params;

    public static class Params {
        private final String repositoryId; // e.g. "platform_rpms-latest"
        private final String name; // e.g. "Platform RPM Latest Repo"
        private final String baseurl;
        private final boolean enabled;

        public Params(String repositoryId,
               String name,
               String baseurl,
               boolean enabled) {
            this.repositoryId = repositoryId;
            this.name = name;
            this.baseurl = baseurl;
            this.enabled = enabled;
        }
    }

    public AddYumRepoTask(Params params) {
        validateRepositoryId(params.repositoryId);
        this.params = params;
        Task.validateVariant(variantName());
    }

    @Override
    public String variantName() {
        return params.repositoryId;
    }

    @Override
    public boolean execute(TaskContext context) {
        Path path = Paths.get("/etc/yum.repos.d",params.repositoryId, ".repo");

        if (path.toFile().exists()) {
            return false;
        }

        WriteFileTask.Params writeFileParams = new WriteFileTask.Params(path, this::getRepoFileContent)
                .withUser("root")
                .withGroup("root")
                .withPermissions("rw-r--r--");

        return context.executeSubtask(new WriteFileTask(writeFileParams));
    }

    String getRepoFileContent() {
        return String.join("\n",
                "# This file was generated by node admin",
                "# Do NOT modify this file by hand",
                "",
                "[" + params.repositoryId + "]",
                "name=" + params.name,
                "baseurl=" + params.baseurl,
                "enabled=" + (params.enabled ? 1 : 0),
                "gpgcheck=0"
        ) + "\n";
    }

    static void validateRepositoryId(String repositoryId) {
        if (!REPOSITORY_ID_PATTERN.matcher(repositoryId).matches()) {
            throw new IllegalArgumentException("Invalid repository ID '" + repositoryId + "'");
        }
    }
}
