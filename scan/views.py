from django.shortcuts import render
from django.http import HttpResponse
from . import Base

def input(request):
    return render(request, 'input.html')

def scan(request):
    a = request.POST['a']
    b = request.POST['b']
    c = request.POST['c']
    d = request.POST['d']
    try:
        thread_num = int(b) if b else 10
    except:
        thread_num = 10

    x = Base.control(thread_num=thread_num,base_domain=c,cookies=d)
    task = []
    task.append(a)
    x.fill_task(task)

    return HttpResponse('Scaning~~~')
