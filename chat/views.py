from django.shortcuts import render

def chat_view(request, room_name):
    return render(request, "chat/chat.html", {"room_name": room_name})
