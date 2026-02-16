from django.urls import include, path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import (
    AssetViewSet,
    ConfigurationItemViewSet,
    ContactViewSet,
    CustomFieldValueViewSet,
    CustomFieldViewSet,
    ChecklistRunItemViewSet,
    ChecklistRunViewSet,
    ChecklistScheduleViewSet,
    DomainViewSet,
    DocumentTemplateViewSet,
    DocumentViewSet,
    DocumentFolderViewSet,
    ChecklistItemViewSet,
    ChecklistViewSet,
    FlexibleAssetTypeViewSet,
    FlexibleAssetViewSet,
    LocationViewSet,
    MeViewSet,
    NotificationViewSet,
    OrganizationViewSet,
    PasswordFolderViewSet,
    PasswordEntryViewSet,
    RelationshipTypeViewSet,
    RelationshipViewSet,
    SearchViewSet,
    SSLCertificateViewSet,
    TagViewSet,
    WebhookEndpointViewSet,
    WorkflowRuleViewSet,
)

router = DefaultRouter()
router.register(r"organizations", OrganizationViewSet, basename="organization")
router.register(r"locations", LocationViewSet, basename="location")
router.register(r"tags", TagViewSet, basename="tag")
router.register(r"contacts", ContactViewSet, basename="contact")
router.register(r"assets", AssetViewSet, basename="asset")
router.register(r"config-items", ConfigurationItemViewSet, basename="configitem")
router.register(r"doc-templates", DocumentTemplateViewSet, basename="doctemplate")
router.register(r"document-folders", DocumentFolderViewSet, basename="documentfolder")
router.register(r"documents", DocumentViewSet, basename="document")
router.register(r"passwords", PasswordEntryViewSet, basename="password")
router.register(r"password-folders", PasswordFolderViewSet, basename="passwordfolder")
router.register(r"domains", DomainViewSet, basename="domain")
router.register(r"ssl-certs", SSLCertificateViewSet, basename="sslcert")
router.register(r"checklists", ChecklistViewSet, basename="checklist")
router.register(r"checklist-items", ChecklistItemViewSet, basename="checklistitem")
router.register(r"checklist-schedules", ChecklistScheduleViewSet, basename="checklistschedule")
router.register(r"checklist-runs", ChecklistRunViewSet, basename="checklistrun")
router.register(r"checklist-run-items", ChecklistRunItemViewSet, basename="checklistrunitem")
router.register(r"flex-asset-types", FlexibleAssetTypeViewSet, basename="flexassettype")
router.register(r"flex-assets", FlexibleAssetViewSet, basename="flexasset")
router.register(r"relationship-types", RelationshipTypeViewSet, basename="relationshiptype")
router.register(r"relationships", RelationshipViewSet, basename="relationship")
router.register(r"custom-fields", CustomFieldViewSet, basename="customfield")
router.register(r"custom-field-values", CustomFieldValueViewSet, basename="customfieldvalue")
router.register(r"search", SearchViewSet, basename="search")
router.register(r"me", MeViewSet, basename="me")
router.register(r"workflow-rules", WorkflowRuleViewSet, basename="workflowrule")
router.register(r"notifications", NotificationViewSet, basename="notification")
router.register(r"webhook-endpoints", WebhookEndpointViewSet, basename="webhookendpoint")

org_router = DefaultRouter()
org_router.register(r"locations", LocationViewSet, basename="org-location")
org_router.register(r"tags", TagViewSet, basename="org-tag")
org_router.register(r"contacts", ContactViewSet, basename="org-contact")
org_router.register(r"assets", AssetViewSet, basename="org-asset")
org_router.register(r"config-items", ConfigurationItemViewSet, basename="org-configitem")
org_router.register(r"doc-templates", DocumentTemplateViewSet, basename="org-doctemplate")
org_router.register(r"document-folders", DocumentFolderViewSet, basename="org-documentfolder")
org_router.register(r"documents", DocumentViewSet, basename="org-document")
org_router.register(r"passwords", PasswordEntryViewSet, basename="org-password")
org_router.register(r"password-folders", PasswordFolderViewSet, basename="org-passwordfolder")
org_router.register(r"domains", DomainViewSet, basename="org-domain")
org_router.register(r"ssl-certs", SSLCertificateViewSet, basename="org-sslcert")
org_router.register(r"checklists", ChecklistViewSet, basename="org-checklist")
org_router.register(r"checklist-items", ChecklistItemViewSet, basename="org-checklistitem")
org_router.register(r"checklist-schedules", ChecklistScheduleViewSet, basename="org-checklistschedule")
org_router.register(r"checklist-runs", ChecklistRunViewSet, basename="org-checklistrun")
org_router.register(r"checklist-run-items", ChecklistRunItemViewSet, basename="org-checklistrunitem")
org_router.register(r"flex-asset-types", FlexibleAssetTypeViewSet, basename="org-flexassettype")
org_router.register(r"flex-assets", FlexibleAssetViewSet, basename="org-flexasset")
org_router.register(r"relationship-types", RelationshipTypeViewSet, basename="org-relationshiptype")
org_router.register(r"relationships", RelationshipViewSet, basename="org-relationship")
org_router.register(r"custom-fields", CustomFieldViewSet, basename="org-customfield")
org_router.register(r"custom-field-values", CustomFieldValueViewSet, basename="org-customfieldvalue")
org_router.register(r"search", SearchViewSet, basename="org-search")
org_router.register(r"workflow-rules", WorkflowRuleViewSet, basename="org-workflowrule")
org_router.register(r"notifications", NotificationViewSet, basename="org-notification")
org_router.register(r"webhook-endpoints", WebhookEndpointViewSet, basename="org-webhookendpoint")

urlpatterns = [
    path("", include(router.urls)),
    path("orgs/<int:org_id>/", include(org_router.urls)),
    path("auth/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
]
