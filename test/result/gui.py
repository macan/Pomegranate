#!/bin/env python

from Tkinter import *

class plot:
    photo = None
    button0 = None
    button1 = None
    button2 = None
    master = None
    id = -1
    maxid = 0
    canvas = None
    item = None
    v = None
    prefix = "mds.g"

    def __init__(self, master, id):
        self.maxid = id
        frame = Frame(master)
        frame.pack()
        self.master = frame

        self.button0 = Button(frame, anchor=S, text="Prev", fg="green", 
                              command=self.toprev)
        self.button0.pack(side = BOTTOM)
        self.button1 = Button(frame, anchor=S, text="Next", fg="red", 
                              command=self.tonext)
        self.button1.pack(side = BOTTOM)
        self.button2 = Button(frame, anchor=S, text="Change", fg="blue",
                              command=self.change)
        self.button2.pack(side = BOTTOM)

        self.v = StringVar()
        Label(self.master, textvariable=self.v).pack()
        self.v.set("Click 'Prev' or 'Next' to view the images.")

        self.canvas = Canvas(self.master, height=600, width=1200)
        self.canvas.pack(side = TOP, fill=BOTH, expand=True)

    def change(self):
        if self.prefix == "mds.g":
            self.prefix = "mdsl.g"
            self.maxid = 7
        elif self.prefix == "mdsl.g":
            self.prefix = "system.n"
            self.maxid = 15
        elif self.prefix == "system.n":
            self.prefix = "system_detail.n"
            self.maxid = 15
        elif self.prefix == "system_detail.n":
            self.prefix = "mds.g"
            self.maxid = 7

    def tonext(self):
        if self.item != None:
            self.canvas.delete(self.item)
        self.id += 1
        if self.id > self.maxid:
            self.id = self.maxid
        try:
            name = self.prefix + str(self.id) + ".gif"
            self.photo = PhotoImage(file=name)
            self.item = self.canvas.create_image(0, 0, image=self.photo, anchor=NW)
            self.v.set("Group ID is %d" % (self.id))
        except:
            self.v.set("Group ID %d not exist!" % (self.id))

    def toprev(self):
        if self.item != None:
            self.canvas.delete(self.item)
        self.id -= 1
        if self.id < 0:
            self.id = 0
        try:
            name = self.prefix + str(self.id) + ".gif"
            self.photo = PhotoImage(file=name)
            self.item = self.canvas.create_image(0, 0, image=self.photo, anchor=NW)
            self.v.set("Group ID is %d" % (self.id))
        except:
            self.v.set("Group ID %d not exist!" % (self.id))

root = Tk()
app = plot(root, 7)

root.mainloop()

