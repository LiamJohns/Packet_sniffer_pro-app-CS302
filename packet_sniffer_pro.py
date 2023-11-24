from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from scapy.all import *
import threading
from PIL import Image, ImageTk
import sys
import os
import tkinter as tk
from tkinter.filedialog import asksaveasfilename

from scapy.layers.l2 import Ether

protocol_names = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IPv4",
    5: "ST",
    6: "TCP",
    7: "CBT",
    8: "EGP",
    9: "IGP",
    10: "BBN-RCC-MON",
    11: "NVP-||",
    12: "PUP",
    13: "ARGUS",
    14: "EMCON",
    15: "XNET",
    16: "CHAOS",
    17: "UDP",
    18: "MUX",
    19: "DCN-MEAS",
    23: "TRUNK-1",
    24: "TRUNK-2",
    33: "DCCP",
    37: "DDP",
    41: "IPv6",

}

class PacketSnifferClass:
    def __init__(self, root):
        self.root = root

        self.start_button = None
        self.stop_button = None
        self.back_button = None
        self.filter_entry = None
        self.apply_filter_button = None
        self.export_packet_button = None
        self.sniffer_exit_button = None
        self.packet_table = None
        self.packet_list = []
        self.filtered_packet_list = []
        self.packet_table_columns = ("Source IP", "Destination IP", "Protocol", "Length(Bytes)", "payload", "Raw")
        self.sniffing_thread = None
        self.sniffing_active = False




    def back_to_menu_command(self):
        landing_page.deiconify()
        landing_page.mainloop()
        self.root.withdraw()


    def create_widgets(self):
        # Start sniffing
        self.start_button = Button(self.root, text="Start", command=self.start_sniffing, width="8", height="1")
        self.start_button.place(relx=0.1, rely=0.1 )

        # Stop sniffing
        self.stop_button = Button(self.root, text="Stop", command=self.stop_sniffing, width="8", height="1")
        self.stop_button.place(relx=0.2, rely=0.1 )
        self.stop_button.configure(state="disabled")

        # back button
        self.back_button = Button(self.root, text="Back", command=self.back_to_menu_command, width=8, height=1 )
        self.back_button.place(relx= 0.0 , rely=0.0)




        # Export packets button

        self.export_packet_button = Button(self.root, text="export", command=self.export_packet_to_pcap, width=8, height=1)
        self.export_packet_button.place(relx=0.8, rely=0.1)




        # Filter entry
        filter_label = Label(self.root, text="IP Filter:")
        filter_label.pack(pady=5)
        self.filter_entry = Entry(self.root, width=30)
        self.filter_entry.pack()





        # Apply filter button
        self.apply_filter_button = Button(self.root, text="Apply Filter", command=self.apply_filter)
        self.apply_filter_button.pack(pady=5)
        self.apply_filter_button.configure(state="disabled")

        # Protocol checklist button
        self.checklist_button = Button(self.root, text="Protocols", command=lambda: protocol_win(self))
        self.checklist_button.place(relx=0.7, rely=0.1)




        # Packet table
        self.packet_table = ttk.Treeview(self.root, columns=self.packet_table_columns, show="headings", height= 20)
        for column in self.packet_table_columns:
            self.packet_table.heading(column, text=column)
        self.packet_table.pack(pady=10, anchor=CENTER)




        #show packet details
        self.show_details_button = Button(self.root, text="Show Details", command=self.show_packet_details)
        self.show_details_button.place(relx=0.5 ,rely=0.9 )

    def export_packet_to_pcap(self):
        selected_item = self.packet_table.selection()
        if selected_item:
            try:
                packet_index = int(selected_item[0][1:]) - 1
                if 0 <= packet_index < len(self.filtered_packet_list):
                    selected_packet = self.filtered_packet_list[packet_index]

                    # Create a Scapy packet object
                    scapy_packet = Ether() / IP(src=selected_packet[0], dst=selected_packet[1]) / selected_packet[5]


                    file_path = asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])


                    if file_path:

                        wrpcap(file_path, scapy_packet)
                        messagebox.showinfo("Export Packet", f"Packet exported to {file_path}")
                else:
                    messagebox.showerror("Error", "Invalid packet selection")
            except (ValueError, IndexError):
                if packet_index is not None:
                    print(packet_index)
                messagebox.showerror("Error", "Invalid packet selection")
        else:
            messagebox.showerror("Error", "No packet selected")

    def show_packet_details(self):
        selected_item = self.packet_table.selection()
        if selected_item:
            try:
                packet_index_str = selected_item[0]
                packet_index = int(packet_index_str[1:]) - 1
                if 0 <= packet_index < len(self.filtered_packet_list):
                    selected_packet = self.filtered_packet_list[packet_index]

                    packet_info_win = tk.Toplevel(self.root)
                    packet_info_win.title("Packet Info")

                    text_widget = tk.Text(packet_info_win, wrap=tk.WORD, width=40, height=15, font=("Arial", 12))
                    text_widget.pack()

                    text_widget.insert(tk.END, f"Source IP: {selected_packet[0]}\n")
                    text_widget.insert(tk.END, f"Destination IP: {selected_packet[1]}\n")
                    text_widget.insert(tk.END, f"Protocol: {selected_packet[2]}\n")
                    text_widget.insert(tk.END, f"Length (bytes): {selected_packet[3]}\n")
                    text_widget.insert(tk.END, f"Payload: {selected_packet[4]}\n")
                    text_widget.insert(tk.END, f"Raw:\n{selected_packet[5]}")
                else:
                    messagebox.showerror("Error", "Invalid packet selection")
            except (ValueError, IndexError):
                messagebox.showerror("Error", "Invalid packet selection")
        else:
            messagebox.showerror("Error", "No packet selected")

    def start_sniffing(self):
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.apply_filter_button.configure(state="normal")
        self.packet_list = []
        self.filtered_packet_list = []
        self.sniffing_active = True
        self.sniffing_thread = threading.Thread(target=self.sniff_packets)
        self.sniffing_thread.start()
        messagebox.showinfo("Start Sniffing", "Packet sniffing started.")


    def sniff_packets(self):
        sniff(prn=self.process_packet, store=False)

    def process_packet(self, packet):
        if self.sniffing_active:
            if packet.haslayer(IP):
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
                protocol_number = packet[IP].proto
                protocol_name = protocol_names.get(protocol_number, "Unknown")
                length = len(packet)
                payload = packet.payload
                raw = packet[Raw].load
                self.packet_list.append((source_ip, destination_ip, protocol_name, length, payload, raw))
                self.apply_filter()
                print(
                    f"Processed packet - Source IP: {source_ip}, Destination IP: {destination_ip}, Protocol: {protocol_name}")

    def stop_sniffing(self):
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.apply_filter_button.configure(state="normal")
        self.sniffing_active = False
        messagebox.showinfo("Stop Sniffing", "Packet sniffing stopping.")

    def update_packet_table(self):
        self.packet_table.delete(*self.packet_table.get_children())
        for index, packet in enumerate(self.filtered_packet_list, start=1):
            item_id = f"I{index}"
            self.packet_table.insert("", index, iid=item_id, values=packet)

    def apply_filter(self):
        filter_text = self.filter_entry.get().lower()
        selected_protocols = set(packet[2].lower() for packet in self.packet_list)
        if filter_text:
            selected_protocols = {protocol for protocol in selected_protocols if filter_text in protocol}

        self.filtered_packet_list = [
            packet for packet in self.packet_list
            if packet[0].lower().startswith(filter_text) or
               packet[1].lower().startswith(filter_text) or
               packet[2].lower().startswith(filter_text) or
               packet[2].lower() in selected_protocols
        ]
        self.update_packet_table()


class ImageCarouselClass:
    def __init__(self, tutorial, back_command):
        self.master = tutorial
        self.images = []
        self.current_image_index = 0

        self.back_command = back_command

        def back_to_menu_command(self):
            if self.back_command is not None:
                self.back_command()

        self.previous_button = tk.Button(tutorial, text="Back", command=self.show_previous_image, width=8, height=1)
        self.previous_button.place(relx=0.1, rely=0.5)

        self.next_button = tk.Button(tutorial, text="Next", command=self.show_next_image, width=8, height=1)
        self.next_button.place(relx=0.9, rely=0.5)

        # back button
        self.back_button = Button(tutorial, text="Back", command=self.back_command, width=8, height=1)
        self.back_button.place(relx=0.0, rely=0.0)


        self.image_label = tk.Label(tutorial, width=900, height=400, background="#64B9CD")
        self.image_label.place(relx=0.5, rely=0.5, anchor=CENTER)

        self.end_tutorial = tk.Button(tutorial, text="End tutorial", command= lambda: [sniffer_win()], width=9, height=1)
        self.end_tutorial.place(relx=0.5, rely=0.8)


        self.previous_button.lift()
        self.next_button.lift()
        self.end_tutorial.lift()

    def end_tutorial_command(self):
       sniffer_win

    def add_image(self, image_path):
        # If running as a PyInstaller executable, adjust the image path
        if hasattr(sys, '_MEIPASS'):
            image_path = os.path.join(sys._MEIPASS, image_path)

        image = Image.open(image_path)
        self.images.append(image)

    def show_image(self):
        image = self.images[self.current_image_index]
        photo = ImageTk.PhotoImage(image)
        self.image_label.configure(image=photo)
        self.image_label.image = photo

    def show_previous_image(self):
        if self.current_image_index > 0:
            self.current_image_index -= 1
            self.show_image()

    def show_next_image(self):
        if self.current_image_index < len(self.images) - 1:
            self.current_image_index += 1
            self.show_image()


def second_win():
    second_win = Toplevel()
    second_win.title("Packet sniffer pro")

    second_win.geometry("800x550")
    second_win_canvas = Canvas(second_win, width=500, height=500, bg="#64B9CD")
    text_label = Label(second_win_canvas, text=" welcome to Packet Sniffer pro would you like a tutorial? ",  font=("Roboto-Serif", 16, "normal"), background="#64B9CD")
    text_label.place(relx=0.2, rely=0.2)


    yes_btn = Button(second_win_canvas, text="Yes", command = lambda: [second_win.withdraw(), tutorial_win()], width="8", height="1")
    yes_btn.place(relx=0.5, rely=0.5)

    no_btn = Button(second_win_canvas, text="No", command = lambda: [second_win.withdraw(), sniffer_win()], width="8", height="1")
    no_btn.place(relx=0.5, rely=0.6)

    second_win_canvas.pack(fill=BOTH, expand=True)

def features_win():
    features_win = Toplevel()
    features_win.title("Features")
    features_win.geometry("1000x700")

    features_canvas = Canvas(features_win, width=1200, height=1000, bg="#64B9CD")
    text_label = Label(features_canvas, text="Features", font=("Roboto-Serif", 20, "normal"), background="#64B9CD")
    text_label.place(relx=0.4, rely=0.1)


    text_label2 = Label(features_canvas, text="-Tutorial to go through basic functions and info ", font=("Roboto-Serif", 16, "normal"), background="#64B9CD")
    text_label2.place(relx=0.2, rely=0.3)


    text_label3 = Label(features_canvas, text="-Simplified sniffer controls to avoid any headaches ", font=("Roboto-Serif", 14, "normal"), background="#64B9CD")
    text_label3.place(relx=0.2, rely=0.4)

    text_label4 = Label(features_canvas, text="-An IP filter", font=("Roboto-Serif", 14, "normal"), background="#64B9CD")
    text_label4.place(relx=0.2, rely=0.5)

    text_label4 = Label(features_canvas, text="-Added The ability to export the packets as a PCAP file.", font=("Roboto-Serif", 14, "normal"), background="#64B9CD")
    text_label4.place(relx=0.2, rely=0.6)

    text_label5 = Label(features_canvas, text="-Added the ability to click on a packet and view more packet info", font=("Roboto-Serif", 14, "normal"), background="#64B9CD")
    text_label5.place(relx=0.2, rely=0.7)

    text_label5 = Label(features_canvas, text="-Added a filter checklist so it's easier to filter out certain protocols(currently unavailable)",font=("Roboto-Serif", 14, "normal"), background="#64B9CD")
    text_label5.place(relx=0.2, rely=0.8)










    feature_back=Button(features_canvas, text="Back", command=features_win.destroy, width="8", height="1")
    feature_back.place(rely=0.0, relx=0.0)

    features_canvas.pack( fill=BOTH, expand=True)

def save_proto_filter(self):
    selected_protocols = [protocol_number for protocol_number, var in self.protocol_checkboxes.items() if var.get() == 1]
    self.packet_sniffer.apply_protocol_filter(selected_protocols)
    self.protocol_win.destroy()



def protocol_win(packet_sniffer):
    protocol_win = Toplevel()
    protocol_win.title("Protocol checklist")
    protocol_win.geometry("400x550")
    protocol_canvas = Canvas(protocol_win, width=1000, height=1000, bg="#64B9CD")


    protocol_checkboxes = {}
    for protocol_number, protocol_name in protocol_names.items():
        var = IntVar()
        Checkbutton(protocol_canvas, text=protocol_name, variable=var).grid(row=protocol_number, sticky=W, pady=2)
        protocol_checkboxes[protocol_number] = var

    def save_proto_filter():
        selected_protocols = [protocol_number for protocol_number, var in protocol_checkboxes.items() if var.get() == 1]
        packet_sniffer.apply_protocol_filter(selected_protocols)
        protocol_win.destroy()

    protocol_win.save_btn = Button(protocol_win, text="Save Selection", command=save_proto_filter, width=10, height=1)

    protocol_canvas.pack(fill=BOTH, expand=True)

def tutorial_win():
     tutorial_win = Toplevel()
     tutorial_win.title("Packet Sniffer Pro tutorial")
     tutorial_win.geometry("900x550")
     tutorial_canvas = Canvas(tutorial_win, width=1000, height=1000, bg="#64B9CD")

     back_command = tutorial_win.withdraw

     def go_back_to_landing():
         tutorial_win.withdraw()
         landing_page.deiconify()

     back_command = go_back_to_landing

     carousel = ImageCarouselClass(tutorial_canvas, back_command)
     carousel.add_image("C:/Users/admin1/Desktop/packet_sniffer_pro/images/image1.jpg")
     carousel.add_image("C:/Users/admin1/Desktop/packet_sniffer_pro/images/image2.jpg")
     carousel.add_image("C:/Users/admin1/Desktop/packet_sniffer_pro/images/image3.jpg")
     carousel.add_image("C:/Users/admin1/Desktop/packet_sniffer_pro/images/image4.jpg")
     carousel.add_image("C:/Users/admin1/Desktop/packet_sniffer_pro/images/image5.jpg")
     carousel.add_image("C:/Users/admin1/Desktop/packet_sniffer_pro/images/image6.jpg")
     carousel.add_image("C:/Users/admin1/Desktop/packet_sniffer_pro/images/image7.jpg")

     # Display current tutorial image
     carousel.show_image()
     tutorial_canvas.pack(fill=BOTH, expand=True)


def sniffer_win():
    sniffer_win = Toplevel()
    sniffer_win.title("Packet Sniffer Pro")
    sniffer_win.geometry("1500x600")
    sniffer_canvas = Canvas(sniffer_win, width=800, height=600, bg="#64B9CD")

    packet_sniffer = PacketSnifferClass(sniffer_canvas)
    sniffer_canvas.pack(expand=True, fill=BOTH)
    packet_sniffer.create_widgets()

    # Pass the packet_sniffer instance to the protocol_win function
    packet_sniffer.protocol_win = lambda: protocol_win(packet_sniffer)

    landing_page.withdraw()


if __name__ == "__main__":
    landing_page = Tk()
    landing_page.resizable(None)
    landing_page.geometry("900x550")
    landing_page.title("Packet sniffer pro")

    landing_canvas = Canvas(landing_page, width=3000, height=3000, bg="#64B9CD")

    messagebox.showwarning("Warning","This application has been created for ethical purposes only, any unethical use of this application will not be endorced by the creator of this app.")

    text_label = Label(landing_canvas, text="Packet Sniffer Pro", font=("Roboto-Serif", 20, "normal"), background="#64B9CD")
    text_label.place(relx=0.4, rely=0.3 )

    enter_btn = Button(landing_canvas, text="Enter", command= lambda: [landing_page.withdraw(), second_win()], width="8", height="1")
    enter_btn.place(relx=0.5 , rely=0.5)

    features_btn = Button(landing_canvas, text="Features", command= features_win, width="8", height="1")
    features_btn.place(relx=0.5 , rely=0.6)

    exit_btn = Button(landing_canvas, text="Exit", command=landing_page.destroy, width="8", height="1")
    exit_btn.place(relx=0.5, rely=0.7)
    landing_canvas.pack(fill=BOTH, expand=True)
    landing_page.mainloop()
