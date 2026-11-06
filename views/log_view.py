from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
import os
from django.http import HttpRequest, HttpResponse,  JsonResponse
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def logfile_content(request):
    logfile_content = ["ReachLink is not configured yet"]
    log_file_path = "/var/log/reachlink/reach_request.log"

    if os.path.exists(log_file_path):
        with open(log_file_path, "r") as file:
            logfile_content = file.readlines()

    logfile_content.reverse()
    return JsonResponse({'log': logfile_content})