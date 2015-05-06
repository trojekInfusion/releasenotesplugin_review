package com.infusion.jenkins.releasenotesplugin;
import hudson.Extension;
import hudson.Launcher;
import hudson.model.BuildListener;
import hudson.model.Item;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import javax.mail.MessagingException;
import javax.mail.Transport;
import javax.mail.internet.MimeMessage;
import javax.servlet.ServletException;

import jenkins.plugins.mailer.tasks.MimeMessageBuilder;
import net.sf.json.JSONObject;

import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.slf4j.LoggerFactory;
import org.slf4j.impl.JDK14LoggerAdapter;

import com.cloudbees.plugins.credentials.CredentialsMatcher;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import com.infusion.relnotesgen.MainInvoker;

/**
 * Sample {@link Builder}.
 *
 * <p>
 * When the user configures the project and enables this builder,
 * {@link DescriptorImpl#newInstance(StaplerRequest)} is invoked
 * and a new {@link ReleaseNotesBuilder} is created. The created
 * instance is persisted to the project configuration XML by using
 * XStream, so this allows you to use instance fields (like {@link #name})
 * to remember the configuration.
 *
 * <p>
 * When a build is performed, the {@link #perform(AbstractBuild, Launcher, BuildListener)}
 * method will be invoked.
 *
 * @author trojek
 */
public class ReleaseNotesBuilder extends Builder {

    public static final CredentialsMatcher CREDENTIALS_MATCHER = CredentialsMatchers.anyOf(new CredentialsMatcher[] {
            CredentialsMatchers.instanceOf(UsernamePasswordCredentialsImpl.class)});

    private final String tag1;
    private final String tag2;
    private final String gitDirectory;
    private final String gitBranch;
    private final String gitUrl;
    private final String gitCredentialsId;
    private final String gitCommitterName;
    private final String gitCommitterMail;
    private final String gitCommitMessageValidationOmmiter;
    private final boolean pushReleaseNotes;
    private final String jiraUrl;
    private final String jiraCredentialsId;
    private final String jiraIssuePattern;
    private final String issueFilterByComponent;
    private final String issueFilterByType;
    private final String issueFilterByLabel;
    private final String issueFilterByStatus;
    private final String issueSortType;
    private final String issueSortPriority;
    private final String reportDirectory;
    private final String reportTemplate;
    private final String mailRecipients;

    // Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
    @DataBoundConstructor
    public ReleaseNotesBuilder(final String tag1, final String tag2, final String gitDirectory, final String gitBranch,
            final String gitUrl, final String gitCredentialsId, final String gitCommitterName,
            final String gitCommitterMail, final String gitCommitMessageValidationOmmiter,
            final boolean pushReleaseNotes, final String jiraUrl, final String jiraCredentialsId,
            final String jiraIssuePattern, final String issueFilterByComponent, final String issueFilterByType,
            final String issueFilterByLabel, final String issueFilterByStatus, final String issueSortType,
            final String issueSortPriority, final String reportDirectory, final String reportTemplate, final String mailRecipients) {
        super();
        this.tag1 = tag1;
        this.tag2 = tag2;
        this.gitDirectory = gitDirectory;
        this.gitBranch = gitBranch;
        this.gitUrl = gitUrl;
        this.gitCredentialsId = gitCredentialsId;
        this.gitCommitterName = gitCommitterName;
        this.gitCommitterMail = gitCommitterMail;
        this.gitCommitMessageValidationOmmiter = gitCommitMessageValidationOmmiter;
        this.pushReleaseNotes = pushReleaseNotes;
        this.jiraUrl = jiraUrl;
        this.jiraCredentialsId = jiraCredentialsId;
        this.jiraIssuePattern = jiraIssuePattern;
        this.issueFilterByComponent = issueFilterByComponent;
        this.issueFilterByType = issueFilterByType;
        this.issueFilterByLabel = issueFilterByLabel;
        this.issueFilterByStatus = issueFilterByStatus;
        this.issueSortType = issueSortType;
        this.issueSortPriority = issueSortPriority;
        this.reportDirectory = reportDirectory;
        this.reportTemplate = reportTemplate;
        this.mailRecipients = mailRecipients;
    }

    /**
     * We'll use this from the <tt>config.jelly</tt>.
     */
    public String getTag1() {
        return tag1;
    }

    public String getTag2() {
        return tag2;
    }

    public String getGitDirectory() {
        return gitDirectory;
    }

    public String getGitBranch() {
        return gitBranch;
    }

    public String getGitUrl() {
        return gitUrl;
    }

    public String getGitCredentialsId() {
        return gitCredentialsId;
    }

    public String getGitCommitterName() {
        return gitCommitterName;
    }

    public String getGitCommitterMail() {
        return gitCommitterMail;
    }

    public String getGitCommitMessageValidationOmmiter() {
        return gitCommitMessageValidationOmmiter;
    }

    public boolean isPushReleaseNotes() {
        return pushReleaseNotes;
    }

    public String getJiraUrl() {
        return jiraUrl;
    }

    public String getJiraCredentialsId() {
        return jiraCredentialsId;
    }

    public String getJiraIssuePattern() {
        return jiraIssuePattern;
    }

    public String getIssueFilterByComponent() {
        return issueFilterByComponent;
    }

    public String getIssueFilterByType() {
        return issueFilterByType;
    }

    public String getIssueFilterByLabel() {
        return issueFilterByLabel;
    }

    public String getIssueFilterByStatus() {
        return issueFilterByStatus;
    }

    public String getIssueSortType() {
        return issueSortType;
    }

    public String getIssueSortPriority() {
        return issueSortPriority;
    }

    public String getReportDirectory() {
        return reportDirectory;
    }

    public String getReportTemplate() {
        return reportTemplate;
    }

    public String getMailRecipients() {
        return mailRecipients;
    }

    @Override
    public boolean perform(final AbstractBuild build, final Launcher launcher, final BuildListener listener) {
        // This is where you 'build' the project.
        final PrintStream jenkinsBuildLog = listener.getLogger();
        try {
            redirectLoggingToJenkinsBuildConsole(jenkinsBuildLog);

            String gitBranch = isNotEmpty(this.gitBranch) ? this.gitBranch : getDescriptor().getGitBranch();
            String gitCommitterName = isNotEmpty(this.gitCommitterName) ? this.gitCommitterName : getDescriptor().getGitCommitterName();
            String gitCommitterMail = isNotEmpty(this.gitCommitterMail) ? this.gitCommitterMail : getDescriptor().getGitCommitterMail();
            String gitCommitMessageValidationOmmiter = isNotEmpty(this.gitCommitMessageValidationOmmiter) ? this.gitCommitMessageValidationOmmiter : getDescriptor().getGitCommitMessageValidationOmmiter();
            String jiraUrl = isNotEmpty(this.jiraUrl) ? this.jiraUrl : getDescriptor().getJiraUrl();
            String jiraIssuePattern = isNotEmpty(this.jiraIssuePattern) ? this.jiraIssuePattern : getDescriptor().getJiraIssuePattern();
            String issueSortType = isNotEmpty(this.issueSortType) ? this.issueSortType : getDescriptor().getIssueSortType();
            String issueSortPriority = isNotEmpty(this.issueSortPriority) ? this.issueSortPriority : getDescriptor().getIssueSortPriority();
            String reportTemplate = isNotEmpty(this.reportTemplate) ? this.reportTemplate : getDescriptor().getReportTemplate();

            StandardUsernamePasswordCredentials gitUsernamePassword = CredentialsProvider.findCredentialById(gitCredentialsId, UsernamePasswordCredentialsImpl.class, build);
            StandardUsernamePasswordCredentials jiraUsernamePassword = CredentialsProvider.findCredentialById(jiraCredentialsId, UsernamePasswordCredentialsImpl.class, build);
            jenkinsBuildLog.println("Founded git credentials " + gitUsernamePassword.getDescription());
            jenkinsBuildLog.println("Founded jira credentials " + jiraUsernamePassword.getDescription());

            File report = new MainInvoker()
                    .tagStart(tag1)
                    .tagEnd(tag2)
                    .pushReleaseNotes(pushReleaseNotes)
                    .gitDirectory(gitDirectory)
                    .gitBranch(gitBranch)
                    .gitUrl(gitUrl)
                    .gitUsername(gitUsernamePassword.getUsername())
                    .gitPassword(gitUsernamePassword.getPassword().getPlainText())
                    .gitCommitterName(gitCommitterName)
                    .gitCommitterMail(gitCommitterMail)
                    .gitCommitMessageValidationOmmiter(gitCommitMessageValidationOmmiter)
                    .jiraUrl(jiraUrl)
                    .jiraUsername(jiraUsernamePassword.getUsername())
                    .jiraPassword(jiraUsernamePassword.getPassword().getPlainText())
                    .jiraIssuePattern(jiraIssuePattern)
                    .issueFilterByComponent(issueFilterByComponent)
                    .issueFilterByType(issueFilterByType)
                    .issueFilterByLabel(issueFilterByLabel)
                    .issueFilterByStatus(issueFilterByStatus)
                    .issueSortType(issueSortType)
                    .issueSortPriority(issueSortPriority)
                    .reportDirectory(reportDirectory)
                    .reportTemplate(reportTemplate)
                    .invoke();

            sendMailWithReleaseNotes(build, listener, report);
        } catch (Exception e) {
            e.printStackTrace(jenkinsBuildLog);
            return false;
        }
        return true;
    }

    private void sendMailWithReleaseNotes(final AbstractBuild build, final BuildListener listener, final File report)
            throws MessagingException, UnsupportedEncodingException, IOException {
        if(isNotEmpty(mailRecipients)) {
            listener.getLogger().println("Sending mail with release notes to: " + mailRecipients);

            String mailContent = new String(Files.readAllBytes(report.toPath()));
            MimeMessage msg = new MimeMessageBuilder()
                    .setListener(listener)
                    .setBody(mailContent)
                    .setMimeType("text/html")
                    .setSubject("Release notes generated")
                    .addRecipients(mailRecipients)
                    .buildMimeMessage();

            msg.addHeader("X-Jenkins-Job", build.getParent().getFullName());

            Transport.send(msg);
        }
    }

    private static boolean isNotEmpty(final String text) {
        return text != null && text.length() > 0;
    }

    private void redirectLoggingToJenkinsBuildConsole(final PrintStream jenkinsBuildLog) throws IllegalArgumentException, IllegalAccessException {
        java.util.logging.Logger logger = findJdkLogger();
        if(logger == null) {
            jenkinsBuildLog.println("[WARN] Couldn't find jdk logger, probably jenkins is using new logging system. Logging won't be visible in console.");
            return;
        }

        logger.addHandler(new Handler() {

            DateFormat dateFormat = new SimpleDateFormat("HH:mm:ss.SSS");

            @Override
            public void publish(final LogRecord logRecord) {
                StringBuilder message = new StringBuilder()
                        .append(dateFormat.format(new Date(logRecord.getMillis())))
                        .append(" ")
                        .append(logRecord.getLevel())
                        .append(" ReleaseNotesLogger - ")
                        .append(logRecord.getMessage());
                jenkinsBuildLog.println(message.toString());
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        });
    }

    private java.util.logging.Logger findJdkLogger() throws IllegalArgumentException, IllegalAccessException {
        org.slf4j.impl.JDK14LoggerAdapter logger = (JDK14LoggerAdapter) LoggerFactory.getLogger(MainInvoker.getLoggerName());
        for(Field field : logger.getClass().getDeclaredFields()) {
            field.setAccessible(true);
            Object object = field.get(logger);
            if(object instanceof java.util.logging.Logger) {
                return (Logger) object;
            }
        }
        return null;
    }

    // Overridden for better type safety.
    // If your plugin doesn't really define any property on Descriptor,
    // you don't have to do this.
    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl)super.getDescriptor();
    }

    /**
     * Descriptor for {@link ReleaseNotesBuilder}. Used as a singleton.
     * The class is marked as public so that it can be accessed from views.
     *
     * <p>
     * See <tt>src/main/resources/hudson/plugins/hello_world/HelloWorldBuilder/*.jelly</tt>
     * for the actual HTML fragment for the configuration screen.
     */
    @Extension // This indicates to Jenkins that this is an implementation of an extension point.
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        /**
         * To persist global configuration information,
         * simply store it in a field and call save().
         *
         * <p>
         * If you don't want fields to be persisted, use <tt>transient</tt>.
         */
        private String gitBranch;
        private String gitCommitterName;
        private String gitCommitterMail;
        private String gitCommitMessageValidationOmmiter;
        private String jiraUrl;
        private String jiraIssuePattern;
        private String issueSortType;
        private String issueSortPriority;
        private String reportTemplate;

        /**
         * In order to load the persisted global configuration, you have to
         * call load() in the constructor.
         */
        public DescriptorImpl() {
            load();
        }

        /**
         * Performs on-the-fly validation of the form field 'name'.
         *
         * @param value
         *      This parameter receives the value that the user has typed.
         * @return
         *      Indicates the outcome of the validation. This is sent to the browser.
         *      <p>
         *      Note that returning {@link FormValidation#error(String)} does not
         *      prevent the form from being saved. It just means that a message
         *      will be displayed to the user.
         */
        public FormValidation doCheckGitDirectory(@QueryParameter final String value)
                throws IOException, ServletException {
            if (value.length() == 0)
                return FormValidation.error("Please set git directory");
            return FormValidation.ok();
        }

        public FormValidation doCheckGitUrl(@QueryParameter final String value)
                throws IOException, ServletException {
            if (value.length() == 0)
                return FormValidation.error("Please set git url");
            return FormValidation.ok();
        }

        @Override
        public boolean isApplicable(final Class<? extends AbstractProject> aClass) {
            // Indicates that this builder can be used with all kinds of project types
            return true;
        }

        /**
         * This human readable name is used in the configuration screen.
         */
        @Override
        public String getDisplayName() {
            return "Release notes plugin";
        }

        @Override
        public boolean configure(final StaplerRequest req, final JSONObject formData) throws FormException {
            // To persist global configuration information,
            // set that to properties and call save().
            gitBranch = formData.getString("gitBranch");
            gitCommitterName = formData.getString("gitCommitterName");
            gitCommitterMail = formData.getString("gitCommitterMail");
            gitCommitMessageValidationOmmiter = formData.getString("gitCommitMessageValidationOmmiter");
            jiraUrl = formData.getString("jiraUrl");
            jiraIssuePattern = formData.getString("jiraIssuePattern");
            issueSortType = formData.getString("issueSortType");
            issueSortPriority = formData.getString("issueSortPriority");
            reportTemplate = formData.getString("reportTemplate");
            // ^Can also use req.bindJSON(this, formData);
            //  (easier when there are many fields; need set* methods for this, like setUseFrench)
            save();
            return super.configure(req,formData);
        }

        /**
         * This method returns true if the global configuration says we should speak French.
         *
         * The method name is bit awkward because global.jelly calls this method to determine
         * the initial state of the checkbox by the naming convention.
         */
        public String getGitBranch() {
            return gitBranch;
        }

        public String getGitCommitterName() {
            return gitCommitterName;
        }

        public String getGitCommitterMail() {
            return gitCommitterMail;
        }

        public String getGitCommitMessageValidationOmmiter() {
            return gitCommitMessageValidationOmmiter;
        }

        public String getJiraUrl() {
            return jiraUrl;
        }

        public String getJiraIssuePattern() {
            return jiraIssuePattern;
        }

        public String getIssueSortType() {
            return issueSortType;
        }

        public String getIssueSortPriority() {
            return issueSortPriority;
        }

        public String getReportTemplate() {
            return reportTemplate;
        }

        public ListBoxModel doFillGitCredentialsIdItems(@AncestorInPath final Item project) {
            if (project == null || !project.hasPermission(Item.CONFIGURE)) {
                return new StandardListBoxModel();
            }
            return new StandardListBoxModel()
                    .withEmptySelection()
                    .withMatching(
                            CREDENTIALS_MATCHER,
                            CredentialsProvider.lookupCredentials(StandardCredentials.class,
                                    project,
                                    ACL.SYSTEM)
                    );
        }

        public ListBoxModel doFillJiraCredentialsIdItems(@AncestorInPath final Item project) {
            return doFillGitCredentialsIdItems(project);
        }
    }
}

